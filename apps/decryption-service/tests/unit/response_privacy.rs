use spr_tvc_protocol::crypto::qos_decrypt;
use spr_tvc_protocol::types::EncryptedResponse;

use super::*;

#[test]
fn replay_keeps_the_signed_response_key_and_cannot_retarget_the_result() {
    let service = service();
    let owner = SigningKey::from_bytes(&[5; 32]);
    let (viewing, _) = service_keys(&service, &owner);
    let request = decrypt(
        &service,
        &owner,
        NETWORK,
        vec![transfer_output(viewing, b"ten usdc", 0)],
    );
    let other_secret = [0x43; 32];
    let other_key = p256::SecretKey::from_slice(&other_secret).unwrap();
    let body = jcs_serialize(&envelope(&service, &request)).unwrap();

    for _ in 0..2 {
        let response = execute(&service, body.as_bytes()).unwrap();
        let envelope: EncryptedResponse = parse_strict_json(&response).unwrap();
        assert!(qos_decrypt(&other_secret, &envelope.encrypted_result).is_err());
        let ServiceResult::Decrypt(result) = open(&service, &request, &response) else {
            panic!("expected a Decrypt result");
        };
        assert_eq!(result.plaintexts, [b"ten usdc".to_vec()]);
    }

    let mut retargeted = request;
    retargeted.client_response_public_key =
        public_key_uncompressed(&other_key.public_key()).to_vec();
    refused(&service, &retargeted);
}
