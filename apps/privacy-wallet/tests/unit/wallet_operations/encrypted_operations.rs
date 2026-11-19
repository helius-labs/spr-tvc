//! The whole encrypted path against the testkit's local custody.

use axum::http::StatusCode;
use serde::Deserialize;
use spr_prover_tee::{decrypt_response, ATTESTATION_PATH, HEADER_ENC, HEADER_VERSION, VERSION};
use spr_tvc_enclave::testing::{encrypt_request, open_response};
use spr_tvc_protocol::auth::authorize_operation_request;
use spr_tvc_protocol::constants::MAX_CLOCK_SKEW_MS;
use spr_tvc_protocol::crypto::{public_key_uncompressed, sign_p256_prehash};
use spr_tvc_protocol::digest::{descriptor_digest, request_digest, sha256};
use spr_tvc_protocol::encoding::{decode_lower_hex_array, jcs_serialize, parse_strict_json};
use spr_tvc_protocol::sign_wallet_grant;
use spr_tvc_protocol::types::{SealedProverRequest, WalletGrant};

use super::*;
use crate::{local_unattested_state, LocalProver, LocalProverTrust, POLICY_PATH};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Keys {
    provisioning_private_key_hex: String,
    grant_private_key_hex: String,
    client_private_key_hex: String,
    organization_id: String,
    wallet_id: String,
    security_domain_label: String,
    manifest_label: String,
    executable_label: String,
    release_id: String,
    quorum_key_id: String,
}

struct Harness {
    state: AppState,
    keys: Keys,
    wallet: TestWallet,
    client_secret: [u8; 32],
    response_secret: [u8; 32],
}

impl Harness {
    fn new(prover: LocalProverTrust) -> Self {
        let keys: Keys = serde_json::from_str(include_str!(
            "../../../../../packages/tvc-wallet/src/local-testkit.json"
        ))
        .expect("testkit");
        let wallet = test_wallet();
        let state = local_unattested_state(wallet.secret, prover);
        Self {
            state,
            client_secret: decode_lower_hex_array(&keys.client_private_key_hex).expect("client"),
            response_secret: [0x42; 32],
            keys,
            wallet,
        }
    }

    /// A descriptor for the testkit client key, signed by the testkit
    /// provisioning key, that expires a day from now.
    fn descriptor(&self) -> WalletDescriptor {
        self.descriptor_expiring(now_ms().expect("clock") + 86_400_000)
    }

    fn descriptor_expiring(&self, expires_at_ms: u64) -> WalletDescriptor {
        let client_public = public_key_uncompressed(
            &p256::SecretKey::from_slice(&self.client_secret)
                .expect("client scalar")
                .public_key(),
        );
        let mut descriptor = WalletDescriptor {
            version: API_VERSION,
            security_domain_id: sha256(self.keys.security_domain_label.as_bytes()),
            network: spr_tvc_enclave::NETWORK,
            turnkey_organization_id: self.keys.organization_id.clone(),
            turnkey_wallet_id: self.keys.wallet_id.clone(),
            address: Pubkey::new_from_array(self.wallet.public_key).to_string(),
            allowed_clients: vec![ClientGrant {
                client_public_key: client_public.to_vec(),
                allowed_operations: OPERATIONS.to_vec(),
            }],
            expires_at_ms,
            provisioning_signature: Vec::new(),
        };
        let provisioning: [u8; 32] =
            decode_lower_hex_array(&self.keys.provisioning_private_key_hex).expect("provisioner");
        descriptor.provisioning_signature = sign_p256_prehash(
            &provisioning,
            &descriptor_digest(&descriptor).expect("digest"),
        )
        .expect("descriptor signature")
        .to_vec();
        descriptor
    }

    fn request(&self, operation: Operation, sealed: Option<Vec<u8>>) -> OperationRequest {
        self.request_under(self.descriptor(), operation, sealed)
    }

    /// `operation` under `descriptor`, signed by the testkit client key.
    fn request_under(
        &self,
        descriptor: WalletDescriptor,
        operation: Operation,
        sealed: Option<Vec<u8>>,
    ) -> OperationRequest {
        let info = &self.state.info;
        let now = now_ms().expect("clock");
        let client_key_id = client_key_id(&descriptor.allowed_clients[0].client_public_key);
        let response_public = public_key_uncompressed(
            &p256::SecretKey::from_slice(&self.response_secret)
                .expect("response scalar")
                .public_key(),
        );
        let request = OperationRequest {
            version: API_VERSION,
            request_id: sha256(b"request"),
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
            target_release_id: self.keys.release_id.clone(),
            target_manifest_digest: sha256(self.keys.manifest_label.as_bytes()),
            target_executable_digest: sha256(self.keys.executable_label.as_bytes()),
            quorum_key_id: self.keys.quorum_key_id.clone(),
            quorum_key_epoch: 1,
            wallet_descriptor: descriptor,
            sealed_seed: sealed,
            client_response_public_key: response_public.to_vec(),
            operation,
            authorization: ClientAuthorization {
                client_key_id,
                signature: Vec::new(),
            },
        };
        assert_eq!(info.release_id, request.target_release_id);
        authorize_operation_request(request, &self.client_secret).expect("authorized")
    }

    /// A grant for `request`'s descriptor and client key, valid from
    /// `issued_at_ms` for `lifetime_ms`, signed by the testkit grant key.
    fn grant(
        &self,
        request: &OperationRequest,
        issued_at_ms: u64,
        lifetime_ms: u64,
    ) -> WalletGrant {
        let unsigned = WalletGrant {
            version: API_VERSION,
            descriptor_digest: descriptor_digest(&request.wallet_descriptor).expect("digest"),
            client_key_id: request.authorization.client_key_id.clone(),
            project_id: "local".to_owned(),
            issued_at_ms,
            expires_at_ms: issued_at_ms + lifetime_ms,
            signature: Vec::new(),
        };
        let secret: [u8; 32] =
            decode_lower_hex_array(&self.keys.grant_private_key_hex).expect("grant key");
        sign_wallet_grant(unsigned, &secret).expect("grant")
    }

    /// Sends one request, with a current grant, through the encrypted
    /// endpoint and opens the answer.
    async fn call(&self, request: &OperationRequest) -> Result<OperationResult, Failure> {
        let grant = self.grant(request, now_ms().expect("clock"), 900_000);
        self.call_with_grant(request, Some(grant)).await
    }

    async fn call_with_grant(
        &self,
        request: &OperationRequest,
        wallet_grant: Option<WalletGrant>,
    ) -> Result<OperationResult, Failure> {
        let request_json = jcs_serialize(request).expect("request");
        let mut envelope = encrypt_request(&self.state.info, &request_json, wallet_grant);
        envelope.quorum_key_id = request.quorum_key_id.clone();
        envelope.quorum_key_epoch = request.quorum_key_epoch;
        let body = jcs_serialize(&envelope).expect("envelope");
        let response = execute(&self.state, body.as_bytes()).await?;
        let (payload, plaintext) =
            open_response(&self.state.info, &response, &self.response_secret);
        assert_eq!(payload.request_id, request.request_id);
        assert_eq!(
            payload.request_digest,
            request_digest(request).expect("digest")
        );
        assert_eq!(payload.operation, request.operation.kind());
        Ok(
            parse_strict_json(std::str::from_utf8(plaintext.as_slice()).expect("utf8"))
                .expect("result"),
        )
    }
}

#[tokio::test]
async fn an_operation_needs_a_current_grant_for_its_descriptor_and_client_key() {
    let harness = Harness::new(LocalProverTrust::StandIn(Anchors::PRODUCTION));
    let request = harness.request(Operation::Bootstrap, None);
    let now = now_ms().expect("clock");

    assert_eq!(
        failure(harness.call_with_grant(&request, None).await),
        Failure::Invalid
    );

    let expired = harness.grant(&request, now - 1_800_000, 900_000 - MAX_CLOCK_SKEW_MS);
    assert_eq!(
        failure(harness.call_with_grant(&request, Some(expired)).await),
        Failure::Invalid
    );

    let mut other_wallet = harness.request(Operation::Bootstrap, None);
    other_wallet.wallet_descriptor.turnkey_wallet_id = "another-wallet".to_owned();
    let foreign = harness.grant(&other_wallet, now, 900_000);
    assert_eq!(
        failure(harness.call_with_grant(&request, Some(foreign)).await),
        Failure::Invalid
    );

    let mut forged = harness.grant(&request, now, 900_000);
    forged.signature = sign_wallet_grant(forged.clone(), &[0x77; 32])
        .expect("grant")
        .signature;
    assert_eq!(
        failure(harness.call_with_grant(&request, Some(forged)).await),
        Failure::Invalid
    );
}

#[tokio::test]
async fn an_expired_descriptor_is_refused_after_the_clock_skew_and_says_so() {
    let harness = Harness::new(LocalProverTrust::StandIn(Anchors::PRODUCTION));
    let now = now_ms().expect("clock");
    let within_skew = harness.descriptor_expiring(now - MAX_CLOCK_SKEW_MS + 10_000);
    let current = harness.request_under(within_skew, Operation::Bootstrap, None);
    assert!(matches!(
        harness.call(&current).await,
        Ok(OperationResult::Bootstrap { .. })
    ));

    let past = harness.descriptor_expiring(now - MAX_CLOCK_SKEW_MS - 1_000);
    let expired = harness.request_under(past, Operation::Bootstrap, None);
    assert_eq!(
        failure(harness.call(&expired).await),
        Failure::DescriptorExpired
    );

    // An expired descriptor whose request another key signed is only invalid.
    let mut unsigned = expired.clone();
    unsigned.authorization.signature = vec![0x01; 64];
    assert_eq!(failure(harness.call(&unsigned).await), Failure::Invalid);
}

#[tokio::test]
async fn the_endpoint_answers_an_expired_descriptor_with_a_403_that_names_it() {
    let response = PublicError::DescriptorExpired.into_response();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), 1_024)
        .await
        .expect("body");
    assert_eq!(&body[..], br#"{"error":"DescriptorExpired"}"#);
}

/// A prover that answers `/prove/<key>` with a fixed proof once the
/// request carries no open secret slot, and records the key and body it
/// was sent.
async fn mock_prover() -> (
    String,
    std::sync::Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>,
) {
    use axum::body::Bytes;
    use axum::extract::Path;
    use axum::routing::post;
    use axum::Router;

    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = std::sync::Arc::clone(&seen);
    let app = Router::new().route(
        "/prove/{key}",
        post(move |Path(key): Path<String>, body: Bytes| {
            let recorded = std::sync::Arc::clone(&recorded);
            async move {
                let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
                recorded.lock().expect("lock").push((key, body));
                let proof = serde_json::json!({
                    "proof": { "ar": ["0x1", "0x2"], "bs": [["0x3", "0x4"], ["0x5", "0x6"]], "krs": ["0x7", "0x8"] }
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(proof.to_string()))
                    .expect("response")
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("address"));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (url, seen)
}

#[tokio::test]
async fn bootstrap_then_every_key_operation_through_the_encrypted_endpoint() {
    let (upstream_url, seen) = mock_prover().await;
    let prover = LocalProver::new(&upstream_url);
    let harness = Harness::new(LocalProverTrust::StandIn(prover.anchors()));
    let prover_url = serve(prover.router()).await;
    let bootstrap = harness.request(Operation::Bootstrap, None);
    let OperationResult::Bootstrap {
        solana_address,
        shielded_owner_hash,
        shielded_viewing_public_key,
        sealed_seed,
        ..
    } = harness.call(&bootstrap).await.expect("bootstrap")
    else {
        panic!("expected a bootstrap result");
    };
    let roles = Roles::from_seed(&harness.wallet.public_key, &harness.wallet.seed).expect("roles");
    assert_eq!(
        solana_address,
        Pubkey::new_from_array(harness.wallet.public_key).to_string()
    );
    assert_eq!(
        shielded_owner_hash,
        roles
            .address()
            .expect("address")
            .owner_hash()
            .expect("owner hash")
    );
    assert!(!sealed_seed
        .windows(64)
        .any(|window| window == harness.wallet.seed));
    let sealed = || Some(sealed_seed.clone());

    let first_nullifier = [7u8; 32];
    let derive = harness.request(
        Operation::Derive {
            items: vec![DeriveItem::MergeOutputBlinding { first_nullifier }],
        },
        sealed(),
    );
    assert_eq!(
        harness.call(&derive).await.expect("derive"),
        keys::derive(
            &roles,
            &[DeriveItem::MergeOutputBlinding { first_nullifier }]
        )
        .expect("expected")
    );

    let transaction_keys = harness.request(
        Operation::TransactionKeys {
            items: vec![TransactionKeyItem {
                viewing_public_key: shielded_viewing_public_key.clone(),
                first_nullifier,
            }],
        },
        sealed(),
    );
    let OperationResult::TransactionKeys { secrets } =
        harness.call(&transaction_keys).await.expect("keys")
    else {
        panic!("expected transaction keys");
    };
    assert_eq!(
        secrets,
        vec![*roles
            .viewing_key
            .get_transaction_viewing_key(&first_nullifier)
            .expect("key")
            .secret_bytes()]
    );

    let prover_sealing = attest(&prover_url, "/prove/merge_1_1").await;
    let prove = harness.request(
        Operation::Prove {
            request: serde_json::json!({
                "circuitType": "merge",
                "inputs": [{ "nullifier": "0x1" }],
                "userNullifierSecret": null,
            }),
            prover: Box::new(prover_sealing.clone()),
        },
        sealed(),
    );
    let OperationResult::Prove { sealed: request } = harness.call(&prove).await.expect("prove")
    else {
        panic!("expected a sealed request");
    };
    // The witness leaves the enclave only as ciphertext; the attested
    // prover opens it and answers under the response key.
    assert!(!request
        .ciphertext
        .windows(18)
        .any(|window| window == b"userNullifierSecre"));
    let proof = submit(&prover_url, &request).await;
    assert_eq!(proof["proof"]["ar"][0], "0x1");
    let expected_secret = format!(
        "0x{}",
        hex::encode(roles.nullifier_key.secret().as_slice()).trim_start_matches('0')
    );
    {
        let sent = seen.lock().expect("lock");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "merge_1_1");
        assert_eq!(sent[0].1["userNullifierSecret"], expected_secret);
    }

    // A bootstrap that presents a state, and a stateful operation that
    // presents none, are rejected before any key is touched.
    let stateful_bootstrap = harness.request(Operation::Bootstrap, sealed());
    assert_eq!(
        harness.call(&stateful_bootstrap).await.unwrap_err(),
        Failure::Invalid
    );
    let stateless_derive = harness.request(derive_nothing(), None);
    assert_eq!(
        harness.call(&stateless_derive).await.unwrap_err(),
        Failure::Invalid
    );
    // A prover request with nothing to fill is refused.
    let idle = harness.request(
        Operation::Prove {
            request: serde_json::json!({
                "circuitType": "merge",
                "inputs": [{}],
                "userNullifierSecret": "0x1",
            }),
            prover: Box::new(prover_sealing),
        },
        sealed(),
    );
    assert_eq!(harness.call(&idle).await.unwrap_err(), Failure::Invalid);
    assert_eq!(seen.lock().expect("lock").len(), 1);
}

#[tokio::test]
async fn a_seed_one_client_key_bootstrapped_serves_another_client_key_of_the_wallet() {
    let prover = LocalProver::new("http://127.0.0.1:1");
    let mut harness = Harness::new(LocalProverTrust::StandIn(prover.anchors()));
    let OperationResult::Bootstrap { sealed_seed, .. } = harness
        .call(&harness.request(Operation::Bootstrap, None))
        .await
        .expect("bootstrap")
    else {
        panic!("expected a bootstrap result");
    };
    let first_nullifier = [7u8; 32];
    let items = vec![DeriveItem::MergeOutputBlinding { first_nullifier }];
    let derive = |harness: &Harness| {
        harness.request(
            Operation::Derive {
                items: items.clone(),
            },
            Some(sealed_seed.clone()),
        )
    };
    let first_request = derive(&harness);
    let first = harness.call(&first_request).await.expect("first key");

    // A new sign-in: another client key, enrolled in its own descriptor.
    harness.client_secret = [0x21; 32];
    let second_request = derive(&harness);
    assert_ne!(
        second_request.wallet_descriptor.allowed_clients,
        first_request.wallet_descriptor.allowed_clients
    );
    assert_eq!(
        harness.call(&second_request).await.expect("second key"),
        first
    );
}

#[tokio::test]
async fn a_refused_attestation_is_a_failure_stage_inside_the_result() {
    let prover = LocalProver::new("http://127.0.0.1:1");
    let harness = Harness::new(LocalProverTrust::StandIn(prover.anchors()));
    let prover_url = serve(prover.router()).await;
    let bootstrap = harness.request(Operation::Bootstrap, None);
    let OperationResult::Bootstrap { sealed_seed, .. } =
        harness.call(&bootstrap).await.expect("bootstrap")
    else {
        panic!("expected a bootstrap result");
    };
    let mut sealing = attest(&prover_url, "/prove/merge_1_1").await;
    sealing.nonce = [0x43; 32];
    let prove = harness.request(
        Operation::Prove {
            request: serde_json::json!({
                "circuitType": "merge",
                "inputs": [{}],
                "userNullifierSecret": null,
            }),
            prover: Box::new(sealing),
        },
        Some(sealed_seed),
    );
    assert_eq!(
        harness.call(&prove).await.expect("answered"),
        OperationResult::Failure {
            operation: OperationKind::Prove,
            stage: FailureStage::Prover,
        }
    );
}

/// A wallet the custodian declines to sign for gets the `TurnkeySigning`
/// stage inside a proven result, not a generic outage.
#[tokio::test]
async fn a_declined_signature_is_a_failure_stage_inside_the_result() {
    let mut harness = Harness::new(LocalProverTrust::StandIn(Anchors::PRODUCTION));
    // The local custodian holds the first wallet's key only.
    harness.wallet = test_wallet();
    let bootstrap = harness.request(Operation::Bootstrap, None);
    assert_eq!(
        harness.call(&bootstrap).await.expect("answered"),
        OperationResult::Failure {
            operation: OperationKind::Bootstrap,
            stage: FailureStage::TurnkeySigning,
        }
    );
}

/// A local enclave trusting the image's network refuses the stand-in's
/// fixture attestation and the testkit-signed policy it publishes.
#[tokio::test]
async fn an_image_trusting_local_enclave_refuses_the_stand_in_prover() {
    let prover = LocalProver::new("http://127.0.0.1:1");
    let harness = Harness::new(LocalProverTrust::Image);
    let prover_url = serve(prover.router()).await;
    let bootstrap = harness.request(Operation::Bootstrap, None);
    let OperationResult::Bootstrap { sealed_seed, .. } =
        harness.call(&bootstrap).await.expect("bootstrap")
    else {
        panic!("expected a bootstrap result");
    };
    let prove = harness.request(
        Operation::Prove {
            request: serde_json::json!({
                "circuitType": "merge",
                "inputs": [{}],
                "userNullifierSecret": null,
            }),
            prover: Box::new(attest(&prover_url, "/prove/merge_1_1").await),
        },
        Some(sealed_seed),
    );
    assert_eq!(
        harness.call(&prove).await.expect("answered"),
        OperationResult::Failure {
            operation: OperationKind::Prove,
            stage: FailureStage::Prover,
        }
    );
}

async fn serve(router: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("address"));
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    url
}

/// The sealing a client builds: the prover's attestation for a fresh
/// nonce and the policy the stand-in prover publishes.
async fn attest(prover_url: &str, target: &str) -> ProverSealing {
    let nonce = [0x42; 32];
    let attestation = reqwest::get(format!(
        "{prover_url}{ATTESTATION_PATH}?nonce={}",
        hex::encode(nonce)
    ))
    .await
    .expect("attestation")
    .json()
    .await
    .expect("attestation json");
    let policy = reqwest::get(format!("{prover_url}{POLICY_PATH}"))
        .await
        .expect("policy")
        .json()
        .await
        .expect("policy json");
    ProverSealing {
        target: target.to_owned(),
        nonce,
        attestation,
        policy,
    }
}

/// Posts a sealed request as a client does and opens the answer.
async fn submit(prover_url: &str, sealed: &SealedProverRequest) -> serde_json::Value {
    let response = reqwest::Client::new()
        .post(format!("{prover_url}{}", sealed.target))
        .header(HEADER_VERSION, VERSION)
        .header(HEADER_ENC, hex::encode(sealed.enc))
        .body(sealed.ciphertext.clone())
        .send()
        .await
        .expect("submit");
    assert_eq!(
        response.headers().get(HEADER_VERSION).expect("encrypted"),
        VERSION
    );
    let encrypted = response.bytes().await.expect("answer");
    let (status, body) = decrypt_response(&sealed.response_key, &encrypted).expect("opens");
    assert_eq!(status, 200);
    serde_json::from_slice(&body).expect("proof json")
}
