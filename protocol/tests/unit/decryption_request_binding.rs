use super::*;
use crate::types::DecryptLabel;

fn request(operation: ServiceOperation) -> ServiceRequest {
    ServiceRequest {
        version: 1,
        request_id: [1; 32],
        target_release_id: "release".to_owned(),
        target_manifest_digest: [2; 32],
        target_executable_digest: [3; 32],
        quorum_key_id: "quorum".to_owned(),
        quorum_key_epoch: 1,
        client_response_public_key: vec![4; 65],
        operation,
    }
}

fn decrypt(signature: [u8; 64], slot_index: u64) -> ServiceOperation {
    ServiceOperation::Decrypt {
        signer: "11111111111111111111111111111111".to_owned(),
        expires_at_ms: 1_795_290_720_000,
        signature,
        items: vec![DecryptItem {
            ciphertext: vec![1, 2, 3],
            ephemeral_viewing_public_key: vec![4; 33],
            salt: vec![0; 16],
            slot_index,
            label: DecryptLabel::Transfer,
        }],
    }
}

#[test]
fn the_decrypt_message_is_a_solana_offchain_message() {
    let message = decrypt_message(&[7; 32], Network::Mainnet, &[9; 32]);
    let payload = format!(
        "TSPP/decryption-service/decrypt/v1/mainnet/{}",
        "09".repeat(32)
    );
    let mut expected = b"\xffsolana offchain\0".to_vec();
    expected.extend_from_slice(&Sha256::digest(b"TSPP/decryption-service/decrypt/v1"));
    expected.extend_from_slice(&[0, 1]);
    expected.extend_from_slice(&[7; 32]);
    expected.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    expected.extend_from_slice(payload.as_bytes());
    assert_eq!(message, expected);
    // The TypeScript client checks the same vector.
    assert_eq!(
        encode_lower_hex(&message),
        concat!(
            "ff736f6c616e61206f6666636861696e005be1ef179167714826436f2f8f69579bd2bd3f7b3ad3cf18e4a0b6a1a0700e",
            "27000107070707070707070707070707070707070707070707070707070707070707076b00545350502f646563727970",
            "74696f6e2d736572766963652f646563727970742f76312f6d61696e6e65742f30393039303930393039303930393039",
            "303930393039303930393039303930393039303930393039303930393039303930393039303930393039303930393039"
        )
    );
    assert_ne!(
        message,
        decrypt_message(&[7; 32], Network::Devnet, &[9; 32]),
        "a message names its network"
    );
}

#[test]
fn the_request_digest_covers_everything_but_the_signature() {
    let digest = service_request_digest(&request(decrypt([0; 64], 0))).unwrap();
    // The TypeScript client checks the same vector.
    assert_eq!(
        encode_lower_hex(&digest),
        "c7756715907ee016a5a564dc38aefb73a50f51db6d5bb568090b7c5871ae99b1"
    );
    assert_eq!(
        digest,
        service_request_digest(&request(decrypt([1; 64], 0))).unwrap()
    );
    assert_ne!(
        digest,
        service_request_digest(&request(decrypt([0; 64], 1))).unwrap()
    );
    let mut other_key = request(decrypt([0; 64], 0));
    other_key.client_response_public_key = vec![5; 65];
    assert_ne!(digest, service_request_digest(&other_key).unwrap());
    let mut other_release = request(decrypt([0; 64], 0));
    other_release.target_release_id = "release-2".to_owned();
    assert_ne!(digest, service_request_digest(&other_release).unwrap());
}

#[test]
fn a_request_parses_strictly() {
    let request = request(ServiceOperation::PublicKeys {
        address: "11111111111111111111111111111111".to_owned(),
    });
    let json = encoding::jcs_serialize(&request).unwrap();
    assert_eq!(parse_service_request(&json).unwrap(), request);
    assert!(parse_service_request(&json.replacen('{', r#"{"extra":1,"#, 1)).is_err());
}

#[test]
fn decrypt_requires_a_canonical_decimal_deadline() {
    let request = request(decrypt([0; 64], 0));
    let mut wire = serde_json::to_value(&request).unwrap();
    assert_eq!(parse_service_request(&wire.to_string()).unwrap(), request);
    for invalid in [
        serde_json::json!(1_795_290_720_000u64),
        serde_json::json!("01795290720000"),
        serde_json::json!("0xff"),
        serde_json::json!("18446744073709551616"),
    ] {
        wire["operation"]["expires_at_ms"] = invalid;
        assert!(parse_service_request(&wire.to_string()).is_err());
    }
    wire["operation"]
        .as_object_mut()
        .unwrap()
        .remove("expires_at_ms");
    assert!(parse_service_request(&wire.to_string()).is_err());
}

#[test]
fn decrypt_items_reject_prerelease_fields() {
    let request = request(decrypt([0; 64], 0));
    let mut wire = serde_json::to_value(&request).unwrap();
    wire["operation"]["items"][0]["viewing_public_key"] = serde_json::json!("04".repeat(33));
    assert!(parse_service_request(&wire.to_string()).is_err());
}
