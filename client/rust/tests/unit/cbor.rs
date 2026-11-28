//! Strict CBOR subset and COSE Sig_structure tests covering INV-14 (shared Rust/TypeScript
//! vectors for canonical decoding, bounded AWS Nitro indefinite root map, outer COSE_Sign1 tag 18,
//! and negative rejection of non-minimal arguments, duplicate/non-scalar map keys, floats, invalid
//! UTF-8, depth overflow, trailing bytes, truncation, and huge unbacked container lengths).

use serde::Deserialize;
use serde_json::Value;

use super::*;

const SHARED_VECTORS: &str = include_str!("../../../../tests/fixtures/cbor-vectors.json");

#[derive(Deserialize)]
struct CborVectors {
    accept: Vec<AcceptVector>,
    reject: Vec<RejectVector>,
    nitro_root: NitroRootVectors,
    cose_sig_structure: CoseSigVector,
}

#[derive(Deserialize)]
struct AcceptVector {
    name: String,
    hex: String,
    kind: String,
    value: Value,
}

#[derive(Deserialize)]
struct RejectVector {
    name: String,
    hex: String,
}

#[derive(Deserialize)]
struct NitroRootVectors {
    accept_hex: String,
    reject: Vec<RejectVector>,
}

#[derive(Deserialize)]
struct CoseSigVector {
    protected_hex: String,
    payload_hex: String,
    expected_hex: String,
}

fn vectors() -> CborVectors {
    serde_json::from_str(SHARED_VECTORS).expect("shared CBOR vectors JSON")
}

fn decode_hex(hex_str: &str) -> Cbor {
    decode_cbor(&hex::decode(hex_str).unwrap()).unwrap()
}

#[test]
fn decodes_the_attestation_subset() {
    for case in vectors().accept {
        let decoded = decode_hex(&case.hex);
        let expected = match case.kind.as_str() {
            "int" => Cbor::Int(case.value.as_i64().unwrap()),
            "bool" => Cbor::Bool(case.value.as_bool().unwrap()),
            "null" => Cbor::Null,
            "bytes" => Cbor::Bytes(hex::decode(case.value.as_str().unwrap()).unwrap()),
            "text" => Cbor::Text(case.value.as_str().unwrap().to_owned()),
            "int_array" => Cbor::Array(
                case.value
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|item| Cbor::Int(item.as_i64().unwrap()))
                    .collect(),
            ),
            other => panic!("unexpected vector kind {other} for {}", case.name),
        };
        assert_eq!(decoded, expected, "shared accept vector {}", case.name);
    }

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
    let nitro = vectors().nitro_root;
    let nitro_root = hex::decode(&nitro.accept_hex).unwrap();
    assert!(decode_cbor(&nitro_root).is_err());
    let Cbor::Map(entries) = decode_nitro_cbor(&nitro_root).unwrap() else {
        panic!("expected root map");
    };
    assert_eq!(entries.len(), 2);

    for case in nitro.reject {
        assert!(
            decode_nitro_cbor(&hex::decode(&case.hex).unwrap()).is_err(),
            "expected Nitro root rejection for {}",
            case.name
        );
    }
}

#[test]
fn rejects_non_minimal_arguments_trailing_bytes_duplicates_floats_depth_and_utf8() {
    for case in vectors().reject {
        assert!(
            decode_cbor(&hex::decode(&case.hex).unwrap()).is_err(),
            "expected rejection for shared vector {}",
            case.name
        );
    }
}

#[test]
fn rejects_huge_container_lengths_without_allocating() {
    let huge: Vec<_> = vectors()
        .reject
        .into_iter()
        .filter(|case| case.name.starts_with("huge_unbacked_"))
        .collect();
    assert_eq!(huge.len(), 2);
    for case in huge {
        assert!(
            decode_cbor(&hex::decode(&case.hex).unwrap()).is_err(),
            "expected rejection for {}",
            case.name
        );
    }
}

#[test]
fn cose_sig_structure_matches_the_canonical_vector() {
    let cose = vectors().cose_sig_structure;
    let encoded = encode_cose_sig_structure(
        &hex::decode(&cose.protected_hex).unwrap(),
        &hex::decode(&cose.payload_hex).unwrap(),
    );
    assert_eq!(hex::encode(&encoded), cose.expected_hex);
}
