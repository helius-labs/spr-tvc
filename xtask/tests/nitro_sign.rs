use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

use super::*;

#[test]
fn signing_distinguishes_activation_and_explicit_revocation() {
    use serde_json::json;

    assert!(
        validate_action(&json!({"action":"activate","recoveryOnly":false,"targets":[{}]})).is_ok()
    );
    assert!(validate_action(&json!({"action":"revoke","recoveryOnly":true,"targets":[]})).is_ok());
    for policy in [
        json!({"action":"activate","recoveryOnly":false,"targets":[]}),
        json!({"action":"revoke","recoveryOnly":true,"targets":[{}]}),
        json!({"targets":[]}),
    ] {
        assert!(validate_action(&policy).is_err());
    }
}

#[test]
fn refuses_to_sign_an_activation_without_pinned_custody_trust() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(br#"{"custodySignatures":[],"policy":{"action":"activate","recoveryOnly":false,"targets":[{}]},"signatures":[]}"#)
        .unwrap();
    let signer = SigningKey::from_bytes(&[1; 32].into()).unwrap();
    let error = sign(Args {
        policy: file.path().to_owned(),
        key: "arn:aws:kms:eu-north-1:000000000001:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
            .to_owned(),
        public_key: encode_lower_hex(signer.verifying_key().to_sec1_point(false).as_bytes()),
        custody_trust: None,
        custody: false,
    })
    .unwrap_err();
    assert_eq!(error.to_string(), "activation requires --custody-trust");
}

#[test]
fn kms_signatures_are_pinned_to_the_key_algorithm_and_exact_manifest() {
    let policy = serde_json::json!({"network":"devnet","sequence":"1"});
    let secret = SigningKey::from_bytes(&[1; 32].into()).unwrap();
    let message = digest(&policy, false).unwrap();
    let signature: Signature = secret.sign_prehash(&message).unwrap();
    let mut response = KmsSignature {
        key_id: "arn-test".to_owned(),
        signing_algorithm: "ECDSA_SHA_256".to_owned(),
        signature: STANDARD.encode(signature.to_der().as_bytes()),
    };
    let public = secret.verifying_key();
    assert!(decode_signature(&response, "arn-test", public, &message).is_ok());
    assert!(decode_signature(&response, "other-key-id", public, &message).is_err());
    assert!(decode_signature(&response, "arn-test", public, &[0; 32]).is_err());
    assert!(decode_signature(
        &response,
        "arn-test",
        public,
        &digest(&policy, true).unwrap()
    )
    .is_err());
    response.signing_algorithm = "ECDSA_SHA_384".to_owned();
    assert!(decode_signature(&response, "arn-test", public, &message).is_err());
}

#[test]
fn custody_signing_digest_matches_the_wire_vector() {
    let policy = serde_json::json!({"sequence":"1","network":"devnet"});
    assert_eq!(
        encode_lower_hex(&digest(&policy, true).unwrap()),
        "8ed7448f3867c9f0f322df52cbcf63866044c8b13032604a4d3f5cfc49547e8a"
    );
}
