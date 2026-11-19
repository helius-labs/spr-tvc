use spr_tvc_protocol::crypto::qos_decrypt;
use spr_tvc_protocol::types::EncryptedResponse;

use super::*;

#[test]
fn replay_keeps_the_signed_response_key_and_cannot_retarget_the_result() {
    let service = service();
    let owner = recipient_signer();
    let (viewing, _) = service_keys(&service, &owner);
    let request = decrypt(
        &service,
        &owner,
        NETWORK,
        vec![transfer_output(viewing, b"ten usdc", 0)],
    );
    let other_secret = [0x43; 32];
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
        public_key_uncompressed(&response_public_key(&other_secret)).to_vec();
    refused(&service, &retargeted);
}

#[test]
fn rejects_invalid_and_compressed_response_keys() {
    use p256::elliptic_curve::sec1::ToEncodedPoint as _;

    let service = service();
    let mut request = public_keys(&service, &recipient_signer());
    let compressed = response_public_key(&RESPONSE_SECRET).to_encoded_point(true);
    for key in [compressed.as_bytes().to_vec(), vec![0; 65]] {
        request.client_response_public_key = key;
        refused(&service, &request);
    }
}
