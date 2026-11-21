use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

use super::*;

#[test]
fn signing_distinguishes_activation_and_explicit_revocation() {
    use serde_json::json;

    assert!(validate_action(&json!({"action":"activate","targets":[{}]})).is_ok());
    assert!(validate_action(&json!({"action":"revoke","targets":[]})).is_ok());
    for policy in [
        json!({"action":"activate","targets":[]}),
        json!({"action":"revoke","targets":[{}]}),
        json!({"targets":[]}),
    ] {
        assert!(validate_action(&policy).is_err());
    }
}

#[test]
fn kms_signatures_are_pinned_to_the_key_algorithm_and_exact_manifest() {
    let policy = serde_json::json!({"network":"devnet","sequence":"1"});
    let secret = SigningKey::from_bytes(&[1; 32].into()).unwrap();
    let message = digest(&policy).unwrap();
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
    response.signing_algorithm = "ECDSA_SHA_384".to_owned();
    assert!(decode_signature(&response, "arn-test", public, &message).is_err());
}
