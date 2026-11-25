//! Inputs for the decrypt bench. Not a supported API.

use qos_p256::P256Pair;
use spr_keypair::viewing_key::Salt;
use spr_keypair::ViewingKey;
use spr_tvc_protocol::body_limit::{max_inner_len, page_decrypt_request, page_inner_json};
use spr_tvc_protocol::constants::{API_VERSION, QOS_ENVELOPE_OVERHEAD};
use spr_tvc_protocol::decryption_service::ServiceOperation;
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
        let mut request = page_decrypt_request();
        let ServiceOperation::Decrypt { items, .. } = &mut request.operation else {
            unreachable!("page request is a Decrypt");
        };
        let page_len = page_inner_json().expect("page json").len();
        let extra = max_inner_len().expect("body cap").saturating_sub(page_len) / 2;
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
