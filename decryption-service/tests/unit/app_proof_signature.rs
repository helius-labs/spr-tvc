use p256::ecdsa::Signature;
use qos_p256::encrypt::P256EncryptPublic;
use qos_p256::P256Pair;
use spr_tvc_wire::constants::{API_VERSION, MAX_ENCRYPTED_RESPONSE_BYTES};
use spr_tvc_wire::decryption_service::{ServiceRequest, ServiceResult};
use zeroize::Zeroizing;

use crate::request::{respond, sign_ephemeral_low_s, Failure};

#[test]
fn qos_signatures_are_normalized_to_low_s_for_the_wire() {
    let message = b"spr tvc low-s interop";
    for seed_byte in 0u8..=u8::MAX {
        let pair = P256Pair::from_master_seed(&Zeroizing::new([seed_byte; 32])).unwrap();
        let raw = pair.sign(message).unwrap();
        let raw = Signature::from_slice(&raw).unwrap();
        if raw.normalize_s() != raw {
            let normalized = sign_ephemeral_low_s(&pair, message).unwrap();
            let normalized = Signature::from_slice(&normalized).unwrap();
            assert_eq!(normalized.normalize_s(), normalized);
            pair.public_key()
                .verify(message, &normalized.to_bytes())
                .unwrap();
            return;
        }
    }
    panic!("fixed QOS seed corpus did not produce a high-S signature");
}

#[test]
fn an_encrypted_result_must_fit_the_response_ceiling() {
    use spr_tvc_wire::decryption_service::{DecryptedOutputs, ServiceOperation};

    let pair = P256Pair::generate().unwrap();
    let request = ServiceRequest {
        version: API_VERSION,
        request_id: [1; 32],
        quorum_key_id: "quorum".into(),
        quorum_key_epoch: 1,
        client_response_public_key: Vec::new(),
        operation: ServiceOperation::Decrypt {
            signer: "unused".into(),
            signature: [0; 64],
            items: Vec::new(),
            grant: None,
        },
    };
    let response_key = P256EncryptPublic::from_bytes(&pair.public_key().to_bytes()[..65]).unwrap();
    let oversized = ServiceResult::Decrypt(DecryptedOutputs {
        nullifier_secret: [0; 31],
        plaintexts: vec![vec![0; MAX_ENCRYPTED_RESPONSE_BYTES as usize / 2]],
    });
    assert_eq!(
        respond(&pair, &request, [0; 32], &response_key, &oversized).unwrap_err(),
        Failure::Unavailable,
    );
}
