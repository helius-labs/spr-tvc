//! Protocol conformance: canonical encoding, P-256, QOS envelope, bindings, and HTTP.

use std::path::PathBuf;
use std::sync::OnceLock;

use p256::elliptic_curve::sec1::ToSec1Point;
use p256::SecretKey;
use sha2::{Digest, Sha256};
use spr_tvc_protocol::constants::API_VERSION;
use spr_tvc_protocol::crypto::{
    parse_uncompressed_sec1, qos_decrypt, sign_p256_prehash, verify_p256_prehash,
};
use spr_tvc_protocol::encoding::{
    canonicalize_json_str, decode_decimal_u64, decode_lower_hex, parse_strict_json,
};
use spr_tvc_protocol::error::ErrorCode;
mod fixtures;

use fixtures::{
    bind_discovery_to_policy, reject_double_hashed_signature, verify_fixtures, write_fixtures,
};
use spr_tvc_protocol::release::verify_signed_release_policy;
use spr_tvc_protocol::types::{HealthResponse, Network, ServiceInfo};
use spr_tvc_protocol::{PinnedReleaseAuthorities, ReleasePolicy, SignedReleasePolicy};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn verify_committed_fixtures() {
    static FIXTURES: OnceLock<()> = OnceLock::new();
    FIXTURES.get_or_init(|| verify_fixtures(&fixtures_dir()).unwrap());
}

#[test]
fn verifies_committed_content_addressed_fixtures() {
    verify_committed_fixtures();
}

#[test]
#[ignore = "run explicitly through `just regenerate-protocol-fixtures`"]
fn regenerate_content_addressed_fixtures() {
    write_fixtures(&fixtures_dir()).unwrap();
    verify_fixtures(&fixtures_dir()).unwrap();
}

#[test]
fn jcs_sorts_keys_and_round_trips() {
    let canonical = canonicalize_json_str(r#"{"b":1,"a":2}"#).unwrap();
    assert_eq!(canonical, r#"{"a":2,"b":1}"#);
    let unicode = canonicalize_json_str(r#"{"é":1,"a":2}"#).unwrap();
    assert!(unicode.starts_with('{'));
}

#[test]
fn canonical_u64_rejects_leading_zeros_and_signs() {
    assert_eq!(decode_decimal_u64("0").unwrap(), 0);
    assert_eq!(
        decode_decimal_u64("1700000000000").unwrap(),
        1_700_000_000_000
    );
    assert_eq!(decode_decimal_u64(&u64::MAX.to_string()).unwrap(), u64::MAX);
    assert_eq!(
        decode_decimal_u64("01").unwrap_err().code,
        ErrorCode::InvalidDecimal
    );
    assert_eq!(
        decode_decimal_u64("+1").unwrap_err().code,
        ErrorCode::InvalidDecimal
    );
    assert_eq!(
        decode_decimal_u64("1.0").unwrap_err().code,
        ErrorCode::InvalidDecimal
    );
}

#[test]
fn unknown_and_duplicate_json_fields_are_rejected() {
    let unknown = parse_strict_json::<HealthResponse>(r#"{"status":"Healthy","extra":true}"#);
    assert_eq!(unknown.unwrap_err().code, ErrorCode::UnknownJsonField);
    let duplicate =
        parse_strict_json::<HealthResponse>(r#"{"status":"Healthy","status":"Healthy"}"#);
    assert_eq!(duplicate.unwrap_err().code, ErrorCode::DuplicateJsonField);
}

#[test]
fn p256_rejects_der_high_s_compressed_and_double_hash() {
    verify_committed_fixtures();
    let body = std::fs::read_to_string(fixtures_dir().join("p256-signatures.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    let public = decode_lower_hex(value["public_key"].as_str().unwrap()).unwrap();
    let digest: [u8; 32] = decode_lower_hex(value["digest"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let raw = decode_lower_hex(value["raw_low_s"].as_str().unwrap()).unwrap();
    let der = decode_lower_hex(value["der"].as_str().unwrap()).unwrap();
    let high = decode_lower_hex(value["high_s"].as_str().unwrap()).unwrap();
    let compressed = decode_lower_hex(value["compressed_public_key"].as_str().unwrap()).unwrap();
    let double_sig = decode_lower_hex(value["double_hash_signature"].as_str().unwrap()).unwrap();

    verify_p256_prehash(&public, &digest, &raw).unwrap();
    assert_eq!(
        verify_p256_prehash(&public, &digest, &der)
            .unwrap_err()
            .code,
        ErrorCode::DerSignatureRejected
    );
    assert_eq!(
        verify_p256_prehash(&public, &digest, &high)
            .unwrap_err()
            .code,
        ErrorCode::HighSSignature
    );
    assert_eq!(
        parse_uncompressed_sec1(&compressed).unwrap_err().code,
        ErrorCode::CompressedKeyRejected
    );
    reject_double_hashed_signature(&public, &digest, &double_sig).unwrap();
}

#[test]
fn qos_envelope_rejects_truncation_and_wrong_key() {
    verify_committed_fixtures();
    let body = std::fs::read_to_string(fixtures_dir().join("qos-negative.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    let truncated = decode_lower_hex(value["truncated_envelope"].as_str().unwrap()).unwrap();
    let envelope = decode_lower_hex(value["envelope"].as_str().unwrap()).unwrap();
    let wrong: [u8; 32] = decode_lower_hex(value["wrong_receiver_secret"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        qos_decrypt(&wrong, &envelope).unwrap_err().code,
        ErrorCode::InvalidEncryptedEnvelope
    );
    assert_eq!(
        qos_decrypt(&wrong, &truncated).unwrap_err().code,
        ErrorCode::InvalidEncryptedEnvelope
    );
}

#[test]
fn health_does_not_leak_deployment_details() {
    verify_committed_fixtures();
    let body = std::fs::read_to_string(fixtures_dir().join("http-skeleton.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["health_body"], r#"{"status":"Healthy"}"#);
    assert_eq!(value["health_has_release_id"], false);
    assert_eq!(value["health_status"], 200);
    let info: ServiceInfo = parse_strict_json(value["info_body"].as_str().unwrap()).unwrap();
    assert_eq!(info.version, API_VERSION);
}

#[test]
fn uppercase_hex_is_rejected() {
    assert_eq!(
        decode_lower_hex("AA").unwrap_err().code,
        ErrorCode::InvalidHex
    );
    assert_eq!(
        decode_lower_hex("0xab").unwrap_err().code,
        ErrorCode::InvalidHex
    );
}

#[test]
fn sign_prehash_is_stable_for_test_scalar() {
    let sk = Sha256::digest(b"spr-tvc-test-client-sk");
    let digest = Sha256::digest(b"digest");
    let a = sign_p256_prehash(&sk.into(), &digest.into()).unwrap();
    let b = sign_p256_prehash(&sk.into(), &digest.into()).unwrap();
    assert_eq!(a, b);
    let _ = SecretKey::from_slice(sk.as_slice())
        .unwrap()
        .public_key()
        .to_sec1_point(false);
}

#[test]
fn discovery_binding_matches_fixture() {
    verify_committed_fixtures();
    let body = std::fs::read_to_string(fixtures_dir().join("discovery-binding.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    let policy: ReleasePolicy = serde_json::from_value(value["policy"].clone()).unwrap();
    let info: ServiceInfo = serde_json::from_value(value["info"].clone()).unwrap();
    bind_discovery_to_policy(&info, &policy).unwrap();
    for case in value["cases"].as_array().unwrap() {
        let mutated: ServiceInfo = serde_json::from_value(case["info"].clone()).unwrap();
        let error = bind_discovery_to_policy(&mutated, &policy).unwrap_err();
        assert_eq!(
            error.code.as_str(),
            case["error"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn signed_release_policy_rejects_empty_duplicate_unknown_and_mutated() {
    verify_committed_fixtures();
    let body = std::fs::read_to_string(fixtures_dir().join("signed-release-policy.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    let signed: SignedReleasePolicy = serde_json::from_value(value["signed"].clone()).unwrap();
    let authorities: PinnedReleaseAuthorities =
        serde_json::from_value(value["authorities"].clone()).unwrap();
    let now_ms = decode_decimal_u64(value["now_ms"].as_str().unwrap()).unwrap();
    let network: Network = serde_json::from_value(value["network"].clone()).unwrap();
    verify_signed_release_policy(&signed, &authorities, network, now_ms).unwrap();
    let mut repeated_key = authorities.clone();
    let mut alias = repeated_key.keys[0].clone();
    alias.key_id = "distinct-id".to_owned();
    repeated_key.keys.push(alias);
    assert_eq!(
        verify_signed_release_policy(&signed, &repeated_key, network, now_ms)
            .unwrap_err()
            .code,
        ErrorCode::ReleasePolicyInvalid,
    );
    assert_eq!(value["empty_signatures"], "ReleasePolicyInvalid");
    assert_eq!(value["duplicate_key_id"], "ReleasePolicyInvalid");
    assert_eq!(value["unknown_key_id"], "ReleasePolicyInvalid");
    assert_eq!(value["mutated_policy"], "InvalidSignature");
    assert_eq!(value["wrong_trust_root"], "ReleasePolicyInvalid");
    assert_eq!(value["revoked_epoch"], "ReleasePolicyInvalid");
    assert_eq!(value["wrong_network"], "NetworkMismatch");
    let other: Network = serde_json::from_value(value["wrong_network_expected"].clone()).unwrap();
    assert_eq!(
        verify_signed_release_policy(&signed, &authorities, other, now_ms)
            .unwrap_err()
            .code,
        ErrorCode::NetworkMismatch
    );
}
