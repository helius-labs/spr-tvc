//! Strict CBOR subset and COSE Sig_structure tests covering INV-14 (positive canonical decoding,
//! bounded AWS Nitro indefinite root map, outer COSE_Sign1 tag 18, and negative rejection of
//! non-minimal arguments, duplicate/non-scalar map keys, floats, invalid UTF-8, depth overflow,
//! trailing bytes, truncation, and huge unbacked container lengths).

use super::*;

fn decode_hex(hex_str: &str) -> Cbor {
    decode_cbor(&hex::decode(hex_str).unwrap()).unwrap()
}

#[test]
fn decodes_the_attestation_subset() {
    assert_eq!(decode_hex("00"), Cbor::Int(0));
    assert_eq!(decode_hex("17"), Cbor::Int(23));
    assert_eq!(decode_hex("1818"), Cbor::Int(24));
    assert_eq!(decode_hex("1903e8"), Cbor::Int(1000));
    assert_eq!(
        decode_hex("1b000001977420dc00"),
        Cbor::Int(1_750_000_000_000)
    );
    assert_eq!(decode_hex("20"), Cbor::Int(-1));
    assert_eq!(decode_hex("f4"), Cbor::Bool(false));
    assert_eq!(decode_hex("f5"), Cbor::Bool(true));
    assert_eq!(decode_hex("f6"), Cbor::Null);
    assert_eq!(decode_hex("43010203"), Cbor::Bytes(vec![1, 2, 3]));
    assert_eq!(decode_hex("6449455446"), Cbor::Text("IETF".into()));
    assert_eq!(
        decode_hex("83010203"),
        Cbor::Array(vec![Cbor::Int(1), Cbor::Int(2), Cbor::Int(3)])
    );
    assert_eq!(
        decode_hex("a2616101010f"),
        Cbor::Map(vec![
            (CborKey::Text("a".into()), Cbor::Int(1)),
            (CborKey::Int(1), Cbor::Int(15)),
        ])
    );
}

#[test]
fn accepts_outer_cose_tag_and_bounded_nitro_indefinite_root_map() {
    // Tag 18 (COSE_Sign1) unwrapped only as the outermost item.
    assert_eq!(decode_hex("d24101"), Cbor::Bytes(vec![1]));
    assert!(decode_cbor(&hex::decode("81d24101").unwrap()).is_err());
    // Unsupported tag (tag 0).
    assert!(
        decode_cbor(&hex::decode("c07818323031332d30332d32315432303a30343a30305a").unwrap())
            .is_err()
    );

    // Bounded indefinite root map accepted by AWS Nitro attestation decoder only.
    let nitro_root = hex::decode("bf696d6f64756c655f6964616d6470637273a10043010203ff").unwrap();
    assert!(decode_cbor(&nitro_root).is_err());
    let Cbor::Map(entries) = decode_nitro_cbor(&nitro_root).unwrap() else {
        panic!("expected root map");
    };
    assert_eq!(entries.len(), 2);

    // Nested indefinite map, duplicate key, missing value, and >32 entries rejected.
    for invalid in [
        hex::decode("bf6161bf616201ffff").unwrap(),
        hex::decode("bf616101616102ff").unwrap(),
        hex::decode("bf6161ff").unwrap(),
    ] {
        assert!(decode_nitro_cbor(&invalid).is_err());
    }
    let mut too_many = vec![0xbf];
    for index in 0u8..33 {
        if index < 24 {
            too_many.push(index);
        } else {
            too_many.extend_from_slice(&[0x18, index]);
        }
        too_many.push(0x00);
    }
    too_many.push(0xff);
    assert!(decode_nitro_cbor(&too_many).is_err());
}

#[test]
fn rejects_non_minimal_arguments_trailing_bytes_duplicates_floats_depth_and_utf8() {
    for invalid_hex in [
        "1800",               // non-minimal u8
        "1817",               // non-minimal u8 (23)
        "190018",             // non-minimal u16
        "1a000003e8",         // non-minimal u32
        "1b00000000000003e8", // non-minimal u64
        "0000",               // trailing byte
        "430102",             // truncated bytes
        "830102",             // truncated array
        "a2616101616102",     // duplicate map key
        "a1810101",           // non-scalar map key
        "f93c00",             // float16
        "fa47c35000",         // float32
        "fb3ff199999999999a", // float64
        "f7",                 // unassigned simple value
        "62c328",             // invalid UTF-8 text string
        "5f42010243030405ff", // indefinite bytes
        "9f01ff",             // indefinite array
    ] {
        assert!(
            decode_cbor(&hex::decode(invalid_hex).unwrap()).is_err(),
            "expected error for {invalid_hex}"
        );
    }
    // Nesting past MAX_DEPTH (16).
    let deep = hex::decode(format!("{}00", "81".repeat(32))).unwrap();
    assert!(decode_cbor(&deep).is_err());
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
