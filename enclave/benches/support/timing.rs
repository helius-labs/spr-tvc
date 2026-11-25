//! Inputs for the decrypt bench. Compiled only with the `bench` feature, which
//! the enclave binary does not enable.

use qos_p256::P256Pair;
use spr_keypair::constants::SALT_LEN;
use spr_keypair::viewing_key::Salt;
use spr_keypair::ViewingKey;
use spr_tvc_protocol::body_limit::max_inner_len;
use spr_tvc_protocol::constants::{API_VERSION, QOS_ENVELOPE_OVERHEAD, SEC1_UNCOMPRESSED_LEN};
use spr_tvc_protocol::decryption_service::{ServiceOperation, X25519_PUBLIC_KEY_LEN};
use spr_tvc_protocol::encoding::jcs_serialize;
use spr_tvc_protocol::types::{DecryptItem, DecryptLabel, EncryptedRequest, ServiceInfo};

use crate::cipher::open_ciphertexts;
use crate::release::NETWORK;
use crate::request::open_envelope;
use crate::Release;

/// One transfer ciphertext, repeated `count` times, under the key that opens it.
pub struct TransferBatch {
    viewing: ViewingKey,
    items: Vec<DecryptItem>,
}

impl TransferBatch {
    pub fn new(count: usize) -> Self {
        let viewing = ViewingKey::new();
        let sender = ViewingKey::new();
        let salt: Salt = [1; 16];
        let ciphertext = sender
            .encrypt_slot(&viewing.pubkey(), b"amount", salt, 0)
            .expect("bench ciphertext");
        let item = DecryptItem {
            ciphertext,
            ephemeral_viewing_public_key: sender.pubkey().as_bytes().to_vec(),
            salt: salt.to_vec(),
            slot_index: 0,
            label: DecryptLabel::Transfer,
        };
        Self {
            viewing,
            items: vec![item; count],
        }
    }

    pub fn open(&self) -> usize {
        open_ciphertexts(&self.viewing, &self.items)
            .expect("bench open")
            .len()
    }
}

/// A QOS envelope at the encrypted body cap.
pub struct MaxEnvelope {
    info: ServiceInfo,
    quorum: P256Pair,
    body: Vec<u8>,
}

impl MaxEnvelope {
    pub fn page() -> Self {
        let quorum = P256Pair::from_master_seed(&[7; 32].into()).expect("bench quorum");
        let mut request = spr_tvc_protocol::decryption_service::ServiceRequest {
            version: API_VERSION,
            request_id: [0; 32],
            target_release_id: String::new(),
            target_manifest_digest: [0; 32],
            target_executable_digest: [0; 32],
            quorum_key_id: String::new(),
            quorum_key_epoch: u64::MAX,
            client_response_public_key: vec![0x04; SEC1_UNCOMPRESSED_LEN],
            operation: ServiceOperation::Decrypt {
                signer: "1".repeat(44),
                signature: [0; 64],
                items: vec![DecryptItem {
                    ciphertext: Vec::new(),
                    ephemeral_viewing_public_key: vec![0x04; X25519_PUBLIC_KEY_LEN],
                    salt: vec![0; SALT_LEN],
                    slot_index: 0,
                    label: DecryptLabel::Transfer,
                }],
            },
        };
        let base = jcs_serialize(&request).expect("bench request").len();
        let extra = max_inner_len().expect("inner cap").saturating_sub(base) / 2;
        let ServiceOperation::Decrypt { items, .. } = &mut request.operation else {
            unreachable!("bench request is a Decrypt");
        };
        items[0].ciphertext.extend(std::iter::repeat_n(0, extra));
        let plaintext = jcs_serialize(&request).expect("max request");
        let ciphertext = quorum
            .public_key()
            .encrypt(plaintext.as_bytes())
            .expect("bench envelope");
        assert_eq!(ciphertext.len(), plaintext.len() + QOS_ENVELOPE_OVERHEAD);
        let body = jcs_serialize(&EncryptedRequest {
            version: API_VERSION,
            quorum_key_id: String::new(),
            quorum_key_epoch: u64::MAX,
            ciphertext,
        })
        .expect("bench request");
        let info = Release {
            security_domain_id: [0; 32],
            release_id: "bench".into(),
            quorum_key_id: String::new(),
            quorum_key_epoch: u64::MAX,
        }
        .service_info([0; 32], [0; 32], &quorum);
        assert_eq!(info.network, NETWORK);
        Self {
            info,
            quorum,
            body: body.into_bytes(),
        }
    }

    pub fn open(&self) -> usize {
        open_envelope(&self.info, &self.quorum, &self.body)
            .expect("bench decrypt")
            .len()
    }
}
