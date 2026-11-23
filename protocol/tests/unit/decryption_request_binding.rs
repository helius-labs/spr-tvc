use super::*;
use crate::error::ErrorCode;
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
        derivation: "11111111111111111111111111111111".to_owned(),
        signer: "11111111111111111111111111111111".to_owned(),
        grant: None,
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
        "31e11ba9039dd52991f81208b07b332ac9e4d6d2f71f328c03faa5978d5d9cfd"
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
fn a_view_grant_window_is_at_most_thirty_minutes() {
    assert!(accept_view_grant_window(1_000, 1_000 + MAX_VIEW_GRANT_WINDOW_MS, 1_000).is_ok());
    assert_eq!(
        accept_view_grant_window(1_000, 1_000 + MAX_VIEW_GRANT_WINDOW_MS + 1, 1_000)
            .unwrap_err()
            .code,
        ErrorCode::ExpiredRequest
    );
    assert!(accept_view_grant_window(5_000, 4_000, 4_500).is_err());
    assert!(accept_view_grant_window(1_000, 2_000, 999).is_err());
    assert!(accept_view_grant_window(1_000, 2_000, 2_001).is_err());
    assert!(accept_view_grant_window(1_000, 1_000, 1_000).is_err());
}

#[test]
fn the_view_grant_message_binds_the_grant_but_not_its_signature() {
    let grant = ViewGrant {
        derivation: "11111111111111111111111111111111".to_owned(),
        grantee: "11111111111111111111111111111112".to_owned(),
        network: Network::Devnet,
        quorum_key_id: "quorum".to_owned(),
        quorum_key_epoch: 4,
        not_before: 1_000,
        expiry: 1_000 + MAX_VIEW_GRANT_WINDOW_MS,
        signature: [0; 64],
    };
    let digest = view_grant_digest(&grant).unwrap();
    let mut signed = grant.clone();
    signed.signature = [9; 64];
    assert_eq!(view_grant_digest(&signed).unwrap(), digest);
    let message = view_grant_message(&[7; 32], &digest);
    let payload = format!(
        "TSPP/decryption-service/view-grant/v1/{}",
        encode_lower_hex(&digest)
    );
    let mut expected = b"\xffsolana offchain\0".to_vec();
    expected.extend_from_slice(&Sha256::digest(b"TSPP/decryption-service/view-grant/v1"));
    expected.extend_from_slice(&[0, 1]);
    expected.extend_from_slice(&[7; 32]);
    expected.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    expected.extend_from_slice(payload.as_bytes());
    assert_eq!(message, expected);
    assert_eq!(
        encode_lower_hex(&digest),
        "c17bed37b80feb7a2cdbe105d7b9db93214cad4dc85d39ed366ce7fe2e4db73c"
    );
    // The TypeScript client checks the same message.
    assert_eq!(
        encode_lower_hex(&message),
        concat!(
            "ff736f6c616e61206f6666636861696e00633f364747049cf5b201551ec5172cbcd6517ff59ad0b38ee572f6fe1b7f8e",
            "15000107070707070707070707070707070707070707070707070707070707070707076600545350502f646563727970",
            "74696f6e2d736572766963652f766965772d6772616e742f76312f633137626564333762383066656237613263646265",
            "31303564376239646239333231346361643464633835643339656433363663653766653265346462373363"
        )
    );
}

#[test]
fn decrypt_items_reject_prerelease_fields() {
    let request = request(decrypt([0; 64], 0));
    let mut wire = serde_json::to_value(&request).unwrap();
    wire["operation"]["items"][0]["viewing_public_key"] = serde_json::json!("04".repeat(33));
    assert!(parse_service_request(&wire.to_string()).is_err());
}
