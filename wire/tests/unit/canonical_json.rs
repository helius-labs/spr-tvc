//! Canonical hex JSON encoding tests for wire requests and decrypted results (INV-11).

use crate::decryption_service::{DecryptedOutputs, ServiceResult};
use crate::types::EncryptedRequest;

use crate::encoding::parse_strict_json;

#[test]
fn results_encode_plaintexts_as_lowercase_hex_strings() {
    let decrypt = ServiceResult::Decrypt(DecryptedOutputs {
        nullifier_secret: [0xab; 31],
        plaintexts: vec![vec![1, 2], Vec::new()],
    });
    let json = serde_json::to_string(&decrypt).unwrap();
    assert_eq!(
        json,
        format!(
            r#"{{"type":"Decrypt","nullifier_secret":"{}","plaintexts":["0102",""]}}"#,
            "ab".repeat(31)
        )
    );
    assert_eq!(parse_strict_json::<ServiceResult>(&json).unwrap(), decrypt);
    for invalid in [json.replace("0102", "0x01"), json.replace("0102", "AB")] {
        assert_eq!(
            parse_strict_json::<ServiceResult>(&invalid)
                .unwrap_err()
                .code,
            crate::error::ErrorCode::InvalidHex,
            "{invalid}"
        );
    }
    assert_eq!(
        parse_strict_json::<ServiceResult>(&json.replace(r#"["0102",""]"#, r#""01""#))
            .unwrap_err()
            .code,
        crate::error::ErrorCode::InvalidCanonicalJson
    );
    assert_eq!(
        parse_strict_json::<EncryptedRequest>(
            r#"{"version":1,"quorum_key_id":"q","quorum_key_epoch":"01","ciphertext":"ff"}"#
        )
        .unwrap_err()
        .code,
        crate::error::ErrorCode::InvalidDecimal
    );
}

#[test]
fn request_ciphertext_is_a_hex_string() {
    let request = r#"{"version":1,"quorum_key_id":"q","quorum_key_epoch":"1","ciphertext":"ff"}"#;
    let parsed = parse_strict_json::<EncryptedRequest>(request).unwrap();
    assert_eq!(parsed.ciphertext, [0xff]);
    assert_eq!(serde_json::to_string(&parsed).unwrap(), request);
}
