//! Gatekeeper client.
//!
//! `keys` and `decrypt` go to `POST /v1/decryption/operations`. The request
//! names the release in the signed pin. Each reply carries the Boot Proof of
//! the replica that signed it, checked with the App Proof before the result opens.

use crate::attestation::{now_ms, BootProof, IdentityPcrs};
use crate::service::{
    bind_operation_proof, shielded_address, CheckReply, Exchange, OpenNotes, ServiceKeys, Target,
    RESPONSE_ENVELOPE_SLACK,
};
use crate::session::{info_from_policy, join, verify_reply_boot, Session};
use crate::transport::Transport;
use crate::{ClientError, OwnerSigner};
use base64::Engine;
use serde::Deserialize;
use spr_keypair::ShieldedAddress;
use spr_tvc_wire::constants::QOS_P256_PUBLIC_LEN;
use spr_tvc_wire::decryption_service::{
    DecryptedOutputs, ServiceOperation, ServiceRequest, ADDRESS_LEN,
};
use spr_tvc_wire::encoding::{decode_lower_hex, parse_strict_json};
use spr_tvc_wire::error::{ErrorCode, TvcError};
use spr_tvc_wire::release::{verify_signed_release_policy, PinnedReleaseAuthorities};
use spr_tvc_wire::types::{
    AppProof, DecryptItem, EncryptedResponse, Network, OperationKind, SignedReleasePolicy,
};

const BOOT_PROOF_SLACK: u64 = 512 * 1024;

/// Where the gatekeeper is, and the API key it expects.
pub struct Gatekeeper {
    pub endpoint: String,
    pub api_key: String,
}

/// Public keys and decrypt through the gatekeeper, with the bundled Boot Proofs checked.
pub struct OperationsClient<T> {
    session: Session<()>,
    transport: T,
    api_key: String,
}

impl<T: Transport> OperationsClient<T> {
    pub fn connect(
        network: Network,
        gatekeeper: Gatekeeper,
        release: SignedReleasePolicy,
        authorities: PinnedReleaseAuthorities,
        pcrs: IdentityPcrs,
        transport: T,
    ) -> Result<Self, ClientError> {
        require_gatekeeper(&gatekeeper.endpoint, &gatekeeper.api_key)?;
        let now = now_ms;
        verify_signed_release_policy(&release, &authorities, network, now())?;
        let info = info_from_policy(&release.policy)?;
        Ok(Self {
            session: Session::verified(gatekeeper.endpoint, info, release, pcrs, now),
            transport,
            api_key: gatekeeper.api_key,
        })
    }

    /// The shielded address a sender pays `owner` at before that owner registers.
    pub fn address(&self, owner: &[u8; ADDRESS_LEN]) -> Result<ShieldedAddress, ClientError> {
        crate::session::ensure_operation(self.session.info(), OperationKind::ServicePublicKeys)?;
        let result = self.call(
            ServiceOperation::PublicKeys {
                address: bs58::encode(owner).into_string(),
            },
            None,
            owner,
        )?;
        shielded_address(owner, result)
    }

    /// Keys for `signer`. Does not call `Decrypt`.
    pub fn keys<'a>(&'a self, signer: &'a dyn OwnerSigner) -> Result<ServiceKeys<'a>, ClientError> {
        let owner = signer.pubkey();
        let address = self.address(&owner)?;
        Ok(ServiceKeys::new(self, signer, address))
    }

    fn call(
        &self,
        operation: ServiceOperation,
        signer: Option<&dyn OwnerSigner>,
        owner: &[u8; ADDRESS_LEN],
    ) -> Result<spr_tvc_wire::decryption_service::ServiceResult, ClientError> {
        Exchange {
            target: Target::from_info(self.session.info()),
            operation,
            signer,
            owner,
            checker: self,
        }
        .run()
    }
}

impl<T: Transport> CheckReply for OperationsClient<T> {
    fn gate(&self) -> Result<(), TvcError> {
        self.session.require_current()
    }

    fn response_overhead(&self) -> u64 {
        RESPONSE_ENVELOPE_SLACK + BOOT_PROOF_SLACK
    }

    fn post_operation(&self, body: &str, limit: usize) -> Result<Vec<u8>, ClientError> {
        self.transport.post_with_api_key(
            &join(self.session.endpoint(), "/v1/decryption/operations"),
            &self.api_key,
            body,
            limit,
        )
    }

    fn open_http(
        &self,
        body: &[u8],
    ) -> Result<(EncryptedResponse, Option<BootProof>), ClientError> {
        let text = std::str::from_utf8(body)
            .map_err(|_| TvcError::new(ErrorCode::InvalidCanonicalJson))?;
        let answer: OperationAnswer = parse_strict_json(text)?;
        let boot = decode_boot_proof(&answer.boot_proof)?;
        Ok((answer.response, Some(boot)))
    }

    fn check_reply(
        &self,
        proof: &AppProof,
        request_digest: &[u8; 32],
        encrypted_result: &[u8],
        request: &ServiceRequest,
        boot: Option<&BootProof>,
    ) -> Result<(), ClientError> {
        let boot = boot.ok_or_else(|| TvcError::new(ErrorCode::BootProofUnverified))?;
        verify_reply_boot(
            self.session.release(),
            self.session.pcrs(),
            proof,
            boot,
            self.session.now_ms(),
        )?;
        bind_operation_proof(proof, request_digest, encrypted_result, request)
    }
}

impl<T: Transport> OpenNotes for OperationsClient<T> {
    fn decrypt_items(
        &self,
        signer: &dyn OwnerSigner,
        items: Vec<DecryptItem>,
    ) -> Result<DecryptedOutputs, ClientError> {
        crate::session::ensure_operation(self.session.info(), OperationKind::ServiceDecrypt)?;
        let owner = signer.pubkey();
        let result = self.call(
            ServiceOperation::Decrypt {
                signer: bs58::encode(owner).into_string(),
                signature: [0; 64],
                items,
                grant: None,
            },
            Some(signer),
            &owner,
        )?;
        match result {
            spr_tvc_wire::decryption_service::ServiceResult::Decrypt(outputs) => Ok(outputs),
            spr_tvc_wire::decryption_service::ServiceResult::PublicKeys { .. } => {
                Err(TvcError::new(ErrorCode::ReleaseBindingMismatch).into())
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireBootProof {
    aws_attestation_doc_b64: String,
    ephemeral_public_key_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationAnswer {
    response: EncryptedResponse,
    boot_proof: WireBootProof,
}

fn decode_boot_proof(wire: &WireBootProof) -> Result<BootProof, TvcError> {
    let attestation = base64::engine::general_purpose::STANDARD
        .decode(wire.aws_attestation_doc_b64.as_bytes())
        .map_err(|_| TvcError::new(ErrorCode::BootProofUnverified))?;
    let key = decode_lower_hex(&wire.ephemeral_public_key_hex)
        .map_err(|_| TvcError::new(ErrorCode::BootProofUnverified))?;
    if key.len() != QOS_P256_PUBLIC_LEN {
        return Err(TvcError::new(ErrorCode::BootProofUnverified));
    }
    let mut ephemeral_public_key = [0u8; QOS_P256_PUBLIC_LEN];
    ephemeral_public_key.copy_from_slice(&key);
    Ok(BootProof {
        attestation,
        ephemeral_public_key,
    })
}

fn require_gatekeeper(endpoint: &str, api_key: &str) -> Result<(), ClientError> {
    let url = reqwest::Url::parse(endpoint).map_err(|_| ClientError::InvalidGatekeeperConfig)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.path() != "/" && !url.path().is_empty())
        || api_key.trim().is_empty()
        || reqwest::header::HeaderValue::from_str(api_key).is_err()
    {
        return Err(ClientError::InvalidGatekeeperConfig);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use base64::Engine;
    use p256::ecdsa::SigningKey;
    use qos_p256::encrypt::P256EncryptPair;
    use serde::Serialize;
    use spr_tvc_wire::constants::{
        API_VERSION, EXPECTED_TURNKEY_TRUST_ROOT_ID, TVC_APP_PROOF_SCHEME,
    };
    use spr_tvc_wire::crypto::sign_p256_message;
    use spr_tvc_wire::decryption_service::parse_service_request;
    use spr_tvc_wire::encoding::{encode_lower_hex, jcs_serialize, parse_strict_json};
    use spr_tvc_wire::error::ErrorCode;
    use spr_tvc_wire::release::{
        sign_release_policy, PinnedReleaseAuthorities, ReleaseAuthorityKey,
    };
    use spr_tvc_wire::types::{
        AppProof, EncryptedRequest, EncryptedResponse, Network, OperationKind,
        ReleaseAuthoritySignature, ReleasePolicy, SignedReleasePolicy,
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
            let signature =
                sign_p256_message(&self.signing_secret, proof_payload.as_bytes()).unwrap();
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
                    aws_attestation_doc_b64: &base64::engine::general_purpose::STANDARD
                        .encode(b"no"),
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

    fn signed_policy(gate: &Gate) -> (SignedReleasePolicy, PinnedReleaseAuthorities) {
        let secret = [4u8; 32];
        let point = SigningKey::from_slice(&secret)
            .unwrap()
            .verifying_key()
            .to_sec1_point(false);
        let policy = ReleasePolicy {
            version: API_VERSION,
            release_id: "release".into(),
            network: Network::Devnet,
            security_domain_id: [0; 32],
            accepted_manifest_digests: vec![encode_lower_hex(&[9; 32])],
            accepted_executable_digests: vec![encode_lower_hex(&[8; 32])],
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
    fn rejects_a_gatekeeper_that_is_not_an_https_origin() {
        let (transport, urls) = gate();
        let (release, authorities) = signed_policy(&transport);
        let Err(error) = OperationsClient::connect(
            Network::Devnet,
            Gatekeeper {
                endpoint: "http://gate.example".into(),
                api_key: "test-key".into(),
            },
            release,
            authorities,
            pcrs(),
            transport,
        ) else {
            panic!("expected the gatekeeper call to fail");
        };
        assert!(matches!(error, ClientError::InvalidGatekeeperConfig));
        assert!(urls.borrow().is_empty());
    }

    #[test]
    fn the_first_operation_checks_the_boot_proof() {
        let (transport, urls) = gate();
        let (release, authorities) = signed_policy(&transport);
        let owner = [7u8; 32];
        let client = OperationsClient::connect(
            Network::Devnet,
            Gatekeeper {
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
}
