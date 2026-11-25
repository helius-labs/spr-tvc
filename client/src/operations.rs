//! A client that only posts `/v1/operations`.
//!
//! The gatekeeper does not expose discovery or the ping. This client encrypts
//! to the quorum key in the caller's release policy and opens the response
//! with its one-time key. It does not check the App Proof or the Nitro document.
//! [`crate::DecryptionClient`] does those checks.

use spr_keypair::ShieldedAddress;
use spr_tvc_protocol::decryption_service::{
    DecryptedOutputs, ServiceOperation, ServiceRequest, ADDRESS_LEN,
};
use spr_tvc_protocol::encoding::decode_lower_hex_array;
use spr_tvc_protocol::error::{ErrorCode, TvcError};
use spr_tvc_protocol::types::{AppProof, DecryptItem, OperationKind, ReleasePolicy};

use crate::attestation::now_ms;
use crate::service::{shielded_address, CheckReply, Exchange, OpenNotes, ServiceKeys, Target};
use crate::transport::Transport;
use crate::{ClientError, OwnerSigner};

/// Public keys and decrypt, with no replica authentication.
pub struct OperationsClient<T> {
    endpoint: String,
    policy: ReleasePolicy,
    transport: T,
}

impl<T: Transport> OperationsClient<T> {
    pub fn new(
        endpoint: impl Into<String>,
        policy: ReleasePolicy,
        transport: T,
    ) -> Result<Self, ClientError> {
        sole_digest(&policy.accepted_manifest_digests)?;
        sole_digest(&policy.accepted_executable_digests)?;
        require_current(&policy, now_ms())?;
        Ok(Self {
            endpoint: endpoint.into(),
            policy,
            transport,
        })
    }

    /// The shielded address a sender pays `owner` at before that owner registers.
    pub fn address(&self, owner: &[u8; ADDRESS_LEN]) -> Result<ShieldedAddress, ClientError> {
        self.allow(OperationKind::ServicePublicKeys)?;
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

    fn allow(&self, kind: OperationKind) -> Result<(), TvcError> {
        if self.policy.allowed_operations.contains(&kind) {
            Ok(())
        } else {
            Err(TvcError::new(ErrorCode::ReleaseBindingMismatch))
        }
    }

    fn call(
        &self,
        operation: ServiceOperation,
        signer: Option<&dyn OwnerSigner>,
        owner: &[u8; ADDRESS_LEN],
    ) -> Result<spr_tvc_protocol::decryption_service::ServiceResult, ClientError> {
        let manifest = sole_digest(&self.policy.accepted_manifest_digests)?;
        let executable = sole_digest(&self.policy.accepted_executable_digests)?;
        let policy = &self.policy;
        Exchange {
            transport: &self.transport,
            endpoint: &self.endpoint,
            target: Target {
                network: policy.network,
                release_id: &policy.release_id,
                manifest_digest: manifest,
                executable_digest: executable,
                quorum_key_id: &policy.quorum_key_id,
                quorum_key_epoch: policy.quorum_key_epoch,
                quorum_public_key: &policy.quorum_public_key,
                max_request: u64::from(policy.max_encrypted_request_bytes),
                max_response: u64::from(policy.max_encrypted_response_bytes),
            },
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
        require_current(&self.policy, now_ms())
    }

    fn check_reply(
        &self,
        _: &AppProof,
        _: &[u8; 32],
        _: &[u8],
        _: &ServiceRequest,
    ) -> Result<(), ClientError> {
        Ok(())
    }
}

impl<T: Transport> OpenNotes for OperationsClient<T> {
    fn decrypt_items(
        &self,
        signer: &dyn OwnerSigner,
        items: Vec<DecryptItem>,
    ) -> Result<DecryptedOutputs, ClientError> {
        self.allow(OperationKind::ServiceDecrypt)?;
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
            spr_tvc_protocol::decryption_service::ServiceResult::Decrypt(outputs) => Ok(outputs),
            spr_tvc_protocol::decryption_service::ServiceResult::PublicKeys { .. } => {
                Err(TvcError::new(ErrorCode::ReleaseBindingMismatch).into())
            }
        }
    }
}

fn sole_digest(digests: &[String]) -> Result<[u8; 32], TvcError> {
    if digests.len() != 1 {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    decode_lower_hex_array(&digests[0])
}

fn require_current(policy: &ReleasePolicy, now: u64) -> Result<(), TvcError> {
    if now < policy.valid_from_ms || now > policy.expires_at_ms {
        return Err(TvcError::new(ErrorCode::ExpiredRequest));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use qos_p256::encrypt::{P256EncryptPair, P256EncryptPublic};
    use spr_tvc_protocol::constants::API_VERSION;
    use spr_tvc_protocol::decryption_service::{ServiceRequest, ServiceResult};
    use spr_tvc_protocol::encoding::{encode_lower_hex, jcs_serialize, parse_strict_json};
    use spr_tvc_protocol::types::{
        AppProof, EncryptedRequest, EncryptedResponse, Network, OperationKind, ReleasePolicy,
    };

    use super::*;

    struct Gate {
        encryption: P256EncryptPair,
        urls: Rc<RefCell<Vec<String>>>,
    }

    impl Transport for Gate {
        fn get(&self, url: &str, _: usize) -> Result<Vec<u8>, ClientError> {
            self.urls.borrow_mut().push(format!("GET {url}"));
            Err(ClientError::Transport)
        }

        fn post(&self, url: &str, body: &str, _: usize) -> Result<Vec<u8>, ClientError> {
            self.urls.borrow_mut().push(format!("POST {url}"));
            let request: EncryptedRequest = parse_strict_json(body).unwrap();
            let inner = self.encryption.decrypt(&request.ciphertext).unwrap();
            let service: ServiceRequest =
                parse_strict_json(std::str::from_utf8(&inner).unwrap()).unwrap();
            let result = ServiceResult::PublicKeys {
                viewing_public_key: {
                    let mut key = [0x04; 33];
                    key[1..].fill(1);
                    key
                },
                nullifier_public_key: [2; 32],
            };
            let plaintext = jcs_serialize(&result).unwrap();
            let response_key =
                P256EncryptPublic::from_bytes(&service.client_response_public_key).unwrap();
            let encrypted = response_key.encrypt(plaintext.as_bytes()).unwrap();
            let response = jcs_serialize(&EncryptedResponse {
                version: API_VERSION,
                request_id: service.request_id,
                encrypted_result: encrypted,
                tvc_app_proof: AppProof {
                    scheme: "unchecked".into(),
                    public_key: vec![4; 65],
                    proof_payload: "not-a-proof".into(),
                    signature: vec![0; 64],
                },
            })
            .unwrap();
            Ok(response.into_bytes())
        }
    }

    #[test]
    fn public_keys_uses_only_operations_and_ignores_the_app_proof() {
        let encryption = P256EncryptPair::generate();
        let signing = P256EncryptPair::generate();
        let mut quorum = Vec::with_capacity(130);
        quorum.extend_from_slice(&encryption.public_key().to_bytes());
        quorum.extend_from_slice(&signing.public_key().to_bytes());
        let urls = Rc::new(RefCell::new(Vec::new()));
        let gate = Gate {
            encryption,
            urls: Rc::clone(&urls),
        };
        let policy = ReleasePolicy {
            version: API_VERSION,
            release_id: "release".into(),
            network: Network::Devnet,
            security_domain_id: [0; 32],
            accepted_manifest_digests: vec![encode_lower_hex(&[9; 32])],
            accepted_executable_digests: vec![encode_lower_hex(&[8; 32])],
            quorum_key_id: "quorum".into(),
            quorum_key_epoch: 1,
            quorum_public_key: quorum,
            allowed_operations: vec![
                OperationKind::ServicePublicKeys,
                OperationKind::ServiceDecrypt,
            ],
            max_encrypted_request_bytes: 1_000_000,
            max_encrypted_response_bytes: 1_000_000,
            turnkey_trust_root_id: "unchecked".into(),
            valid_from_ms: 0,
            expires_at_ms: u64::MAX,
            revocation_epoch: 0,
        };
        let client = OperationsClient::new("https://gate.example", policy, gate).unwrap();
        let address = client.address(&[7; 32]).unwrap();
        assert_eq!(address.viewing_pubkey.as_bytes()[0], 0x04);
        assert_eq!(address.nullifier_pubkey, [2; 32]);
        assert_eq!(
            urls.borrow().as_slice(),
            ["POST https://gate.example/v1/operations"]
        );
    }
}
