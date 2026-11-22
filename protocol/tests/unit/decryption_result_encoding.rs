use super::*;

#[test]
fn directly_serialized_results_keep_the_canonical_wire_bytes() {
    let keys = ServiceResult::PublicKeys {
        viewing_public_key: [0xab; X25519_PUBLIC_KEY_LEN],
        nullifier_public_key: [0xcd; 32],
    };
    let key_json = format!(
        r#"{{"nullifier_public_key":"{}","type":"PublicKeys","viewing_public_key":"{}"}}"#,
        "cd".repeat(32),
        "ab".repeat(X25519_PUBLIC_KEY_LEN),
    );
    let results = [
        (keys, key_json),
        (
            ServiceResult::Decrypt(DecryptedOutputs {
                nullifier_secret: [0x12; NULLIFIER_SECRET_LEN],
                plaintexts: vec![vec![], vec![0x34; 64], vec![0x56; 65]],
            }),
            format!(
                r#"{{"nullifier_secret":"{}","plaintexts":["","{}","{}"],"type":"Decrypt"}}"#,
                "12".repeat(NULLIFIER_SECRET_LEN),
                "34".repeat(64),
                "56".repeat(65),
            ),
        ),
    ];
    for (result, expected) in results {
        let encoded = result.encode_for_encryption().unwrap();
        assert_eq!(encoded.as_slice(), expected.as_bytes());
        assert_eq!(
            serde_json::from_slice::<ServiceResult>(&encoded).unwrap(),
            result
        );
    }
}

#[test]
fn plaintext_above_the_response_ceiling_cannot_grow_the_output_buffer() {
    let result = |length| {
        ServiceResult::Decrypt(DecryptedOutputs {
            nullifier_secret: [0; NULLIFIER_SECRET_LEN],
            plaintexts: vec![vec![0xa5; length]],
        })
    };
    let fixed = result(0).encode_for_encryption().unwrap().len();
    let max_note_size = (MAX_ENCRYPTED_RESPONSE_BYTES as usize - fixed) / 2;
    assert_eq!(
        result(max_note_size).encode_for_encryption().unwrap().len(),
        fixed + 2 * max_note_size,
    );
    assert!(result(max_note_size + 1).encode_for_encryption().is_err());
}
