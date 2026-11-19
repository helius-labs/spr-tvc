use crate::types::{EncryptedRequest, OperationResult};

use super::parse_strict_json;

#[test]
fn hex_fields_are_strings_alone_optional_or_in_arrays() {
    let derive = OperationResult::Derive {
        values: vec![[0xab; 32]],
    };
    let json = format!(r#"{{"type":"Derive","values":["{}"]}}"#, "ab".repeat(32));
    assert_eq!(serde_json::to_string(&derive).unwrap(), json);
    assert_eq!(parse_strict_json::<OperationResult>(&json).unwrap(), derive);

    let decrypt = OperationResult::Decrypt {
        plaintexts: vec![vec![1, 2], Vec::new()],
    };
    let json = r#"{"type":"Decrypt","plaintexts":["0102",""]}"#;
    assert_eq!(serde_json::to_string(&decrypt).unwrap(), json);
    assert_eq!(parse_strict_json::<OperationResult>(json).unwrap(), decrypt);

    let request = r#"{"version":1,"quorum_key_id":"q","quorum_key_epoch":"1","ciphertext":"ff"}"#;
    let parsed = parse_strict_json::<EncryptedRequest>(request).unwrap();
    assert_eq!(parsed.ciphertext, [0xff]);
    assert_eq!(serde_json::to_string(&parsed).unwrap(), request);

    for invalid in [
        r#"{"type":"Derive","values":["AB"]}"#,
        r#"{"type":"Derive","values":["abab"]}"#,
        r#"{"type":"Decrypt","plaintexts":["0x01"]}"#,
        r#"{"type":"Decrypt","plaintexts":"01"}"#,
    ] {
        assert!(
            parse_strict_json::<OperationResult>(invalid).is_err(),
            "{invalid}"
        );
    }
}
