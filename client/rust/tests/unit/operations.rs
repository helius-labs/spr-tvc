//! Operations client tests covering INV-18 (authenticated replica reply & Boot Proof verification),
//! INV-20 (fail-closed unpinned mainnet), and INV-28 (HTTPS origin enforcement).

use std::cell::RefCell;
use std::rc::Rc;

use base64::Engine;
use p256::ecdsa::SigningKey;
use qos_p256::encrypt::P256EncryptPair;
use serde::Serialize;
use spr_tvc_wire::constants::{API_VERSION, EXPECTED_TURNKEY_TRUST_ROOT_ID, TVC_APP_PROOF_SCHEME};
use spr_tvc_wire::crypto::sign_p256_message;
use spr_tvc_wire::decryption_service::parse_service_request;
use spr_tvc_wire::encoding::{encode_lower_hex, jcs_serialize, parse_strict_json};
use spr_tvc_wire::error::ErrorCode;
use spr_tvc_wire::release::{sign_release_policy, PinnedReleaseAuthorities, ReleaseAuthorityKey};
use spr_tvc_wire::types::{
    AppProof, EncryptedRequest, EncryptedResponse, ManifestSetMember, ManifestSetPolicy, Network,
    OperationKind, ReleaseAuthoritySignature, ReleasePolicy, SignedReleasePolicy,
};

use super::*;

struct Gate {
    encryption: P256EncryptPair,
    urls: Rc<RefCell<Vec<String>>>,
    signing_secret: [u8; 32],
    ephemeral: Vec<u8>,
}

impl Transport for Gate {
    fn get(&self, url: &str, _: usize) -> Result<Vec<u8>, ClientError> {
        self.urls.borrow_mut().push(format!("GET {url}"));
        Err(ClientError::Transport)
    }

    fn post(&self, url: &str, _: &str, _: usize) -> Result<Vec<u8>, ClientError> {
        self.urls.borrow_mut().push(format!("POST {url}"));
        Err(ClientError::Transport)
    }

    fn post_with_api_key(
        &self,
        url: &str,
        api_key: &str,
        body: &str,
        _: usize,
    ) -> Result<Vec<u8>, ClientError> {
        assert_eq!(api_key, "test-key");
        self.urls.borrow_mut().push(format!("POST {url}"));
        let request: EncryptedRequest = parse_strict_json(body).unwrap();
        let inner = self.encryption.decrypt(&request.ciphertext).unwrap();
        let inner = std::str::from_utf8(&inner).unwrap();
        let service = parse_service_request(inner).unwrap();
        let proof_payload = "{}";
        let signature = sign_p256_message(&self.signing_secret, proof_payload.as_bytes()).unwrap();
        let answer = OperationWire {
            response: EncryptedResponse {
                version: API_VERSION,
                request_id: service.request_id,
                encrypted_result: vec![0],
                tvc_app_proof: AppProof {
                    scheme: TVC_APP_PROOF_SCHEME.into(),
                    public_key: self.ephemeral.clone(),
                    proof_payload: proof_payload.into(),
                    signature: signature.to_vec(),
                },
            },
            boot_proof: Wire {
                aws_attestation_doc_b64: &base64::engine::general_purpose::STANDARD.encode(b"no"),
                ephemeral_public_key_hex: &encode_lower_hex(&self.ephemeral),
            },
        };
        Ok(jcs_serialize(&answer).unwrap().into_bytes())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationWire<'a> {
    response: EncryptedResponse,
    boot_proof: Wire<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Wire<'a> {
    aws_attestation_doc_b64: &'a str,
    ephemeral_public_key_hex: &'a str,
}

fn test_manifest_set() -> ManifestSetPolicy {
    const GENERATOR: [u8; 65] = [
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
        0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40,
        0x68, 0x37, 0xbf, 0x51, 0xf5,
    ];
    ManifestSetPolicy {
        threshold: 1,
        members: vec![ManifestSetMember {
            alias: "fixture-operator".into(),
            public_key: [GENERATOR, GENERATOR].concat(),
        }],
    }
}

fn signed_policy(gate: &Gate) -> (SignedReleasePolicy, PinnedReleaseAuthorities) {
    let secret = [4u8; 32];
    let point = SigningKey::from_slice(&secret)
        .unwrap()
        .verifying_key()
        .to_sec1_point(false);
    let policy = ReleasePolicy {
        version: API_VERSION,
        network: Network::Devnet,
        security_domain_id: [0; 32],
        namespace: "fixture-namespace".into(),
        manifest_set: test_manifest_set(),
        minimum_manifest_nonce: 0,
        quorum_key_id: "quorum".into(),
        quorum_key_epoch: 1,
        quorum_public_key: gate.ephemeral.clone(),
        allowed_operations: vec![
            OperationKind::ServicePublicKeys,
            OperationKind::ServiceDecrypt,
        ],
        max_encrypted_request_bytes: 1_000_000,
        max_encrypted_response_bytes: 1_000_000,
        turnkey_trust_root_id: EXPECTED_TURNKEY_TRUST_ROOT_ID.into(),
        valid_from_ms: 0,
        expires_at_ms: u64::MAX,
        revocation_epoch: 0,
    };
    let signature = sign_release_policy(&policy, &secret).unwrap();
    let signed = SignedReleasePolicy {
        policy,
        authority_set_id: "authorities".into(),
        signatures: vec![ReleaseAuthoritySignature {
            key_id: "authority".into(),
            signature: signature.to_vec(),
        }],
    };
    let authorities = PinnedReleaseAuthorities {
        authority_set_id: "authorities".into(),
        threshold: 1,
        keys: vec![ReleaseAuthorityKey {
            key_id: "authority".into(),
            public_key: point.as_bytes().to_vec(),
        }],
        minimum_revocation_epoch: 0,
    };
    (signed, authorities)
}

fn gate() -> (Gate, Rc<RefCell<Vec<String>>>) {
    let encryption = P256EncryptPair::generate();
    let signing_secret = [5u8; 32];
    let point = SigningKey::from_slice(&signing_secret)
        .unwrap()
        .verifying_key()
        .to_sec1_point(false);
    let mut ephemeral = Vec::new();
    ephemeral.extend_from_slice(&encryption.public_key().to_bytes());
    ephemeral.extend_from_slice(point.as_bytes());
    let urls = Rc::new(RefCell::new(Vec::new()));
    (
        Gate {
            encryption,
            urls: Rc::clone(&urls),
            signing_secret,
            ephemeral,
        },
        urls,
    )
}

fn pcrs() -> IdentityPcrs {
    IdentityPcrs {
        pcr0: [1; 48],
        pcr1: [1; 48],
        pcr2: [1; 48],
        pcr3: [1; 48],
    }
}

#[test]
fn rejects_an_endpoint_that_is_not_an_https_origin() {
    let (transport, urls) = gate();
    let (release, authorities) = signed_policy(&transport);
    let Err(error) = OperationsClient::connect(
        Network::Devnet,
        OperationsConfig {
            endpoint: "http://gate.example".into(),
            api_key: "test-key".into(),
        },
        release,
        authorities,
        pcrs(),
        transport,
    ) else {
        panic!("expected the endpoint to be refused");
    };
    assert!(matches!(error, ClientError::InvalidServiceConfig));
    assert!(urls.borrow().is_empty());
}

#[test]
fn the_first_operation_checks_the_boot_proof() {
    let (transport, urls) = gate();
    let (release, authorities) = signed_policy(&transport);
    let owner = [7u8; 32];
    let client = OperationsClient::connect(
        Network::Devnet,
        OperationsConfig {
            endpoint: "https://gate.example".into(),
            api_key: "test-key".into(),
        },
        release,
        authorities,
        pcrs(),
        transport,
    )
    .expect("the pin is enough to connect");
    assert!(urls.borrow().is_empty());
    let Err(error) = client.address(&owner) else {
        panic!("expected the boot proof to fail");
    };
    assert!(matches!(
        error,
        ClientError::Protocol(ref protocol) if protocol.code == ErrorCode::BootProofUnverified
    ));
    assert_eq!(
        urls.borrow().as_slice(),
        ["POST https://gate.example/v1/decryption/operations"]
    );
}

#[test]
fn rejects_unpinned_mainnet_before_connecting() {
    let (transport, urls) = gate();
    let (release, authorities) = signed_policy(&transport);
    let Err(error) = OperationsClient::connect(
        Network::Mainnet,
        OperationsConfig {
            endpoint: "https://gate.example".into(),
            api_key: "test-key".into(),
        },
        release,
        authorities,
        pcrs(),
        transport,
    ) else {
        panic!("expected unpinned mainnet to fail closed");
    };
    assert!(matches!(
        error,
        ClientError::Protocol(ref protocol) if protocol.code == ErrorCode::ReleaseNotPinned
    ));
    assert!(urls.borrow().is_empty());
}
