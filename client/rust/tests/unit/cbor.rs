//! Strict CBOR subset and COSE Sig_structure tests covering INV-14 (positive canonical decoding
//! and negative rejection of non-minimal arguments, trailing bytes, and huge container lengths).

use super::*;

fn decode_hex(hex_str: &str) -> Cbor {
    decode_cbor(&hex::decode(hex_str).unwrap()).unwrap()
}

#[test]
fn decodes_the_attestation_subset() {
    assert_eq!(decode_hex("00"), Cbor::Int(0));
    assert_eq!(decode_hex("1818"), Cbor::Int(24));
    assert_eq!(decode_hex("1903e8"), Cbor::Int(1000));
    assert_eq!(
        decode_hex("1b000001977420dc00"),
        Cbor::Int(1_750_000_000_000)
    );
    assert_eq!(decode_hex("20"), Cbor::Int(-1));
    assert_eq!(decode_hex("f6"), Cbor::Null);
    assert_eq!(decode_hex("6449455446"), Cbor::Text("IETF".into()));
    assert_eq!(
        decode_hex("83010203"),
        Cbor::Array(vec![Cbor::Int(1), Cbor::Int(2), Cbor::Int(3)])
    );
}

#[test]
fn rejects_non_minimal_arguments_and_trailing_bytes() {
    assert!(decode_cbor(&hex::decode("1800").unwrap()).is_err());
    assert!(decode_cbor(&hex::decode("0000").unwrap()).is_err());
}

#[test]
fn rejects_huge_container_lengths_without_allocating() {
    // Definite array and map claiming 2^32 entries with zero body bytes.
    assert!(decode_cbor(&hex::decode("9b0000000100000000").unwrap()).is_err());
    assert!(decode_cbor(&hex::decode("bb0000000100000000").unwrap()).is_err());
}

#[test]
fn cose_sig_structure_matches_the_canonical_vector() {
    let encoded = encode_cose_sig_structure(&[0xa1, 0x01, 0x38], &[1, 2, 3, 4, 5]);
    assert_eq!(
        hex::encode(&encoded),
        "846a5369676e61747572653143a1013840450102030405"
    );
}
