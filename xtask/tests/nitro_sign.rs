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
fn refuses_to_sign_without_pinned_publications() {
    let error = Args::try_parse_from([
        "nitro-sign",
        "policy.json",
        "--key",
        "fixture",
        "--public-key",
        "fixture",
    ])
    .err()
    .expect("custody trust is required");
    assert!(error.to_string().contains("--custody-trust"));
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

#[test]
fn concurrent_signatures_cannot_overwrite_an_updated_policy() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.json");
    std::fs::write(&path, "unsigned").unwrap();
    let (first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(|| store_signed_policy(&path, "unsigned", "first"));
        let second = scope.spawn(|| store_signed_policy(&path, "unsigned", "second"));
        (first.join().unwrap(), second.join().unwrap())
    });
    assert_ne!(first.is_ok(), second.is_ok());
    let latest = read_policy(&path).unwrap();
    assert_eq!(latest, if first.is_ok() { "first" } else { "second" });
    let stale = store_signed_policy(&path, "unsigned", "stale").unwrap_err();
    assert!(stale.to_string().contains("policy changed during signing"));
    store_signed_policy(&path, &latest, "both").unwrap();
    assert_eq!(read_policy(&path).unwrap(), "both");
}

#[cfg(unix)]
#[test]
fn refuses_named_pipes_and_symbolic_links_as_signing_inputs() {
    let directory = tempfile::tempdir().unwrap();
    let pipe = directory.path().join("pipe.json");
    assert!(Command::new("mkfifo")
        .arg(&pipe)
        .status()
        .unwrap()
        .success());
    let link = directory.path().join("link.json");
    std::fs::write(directory.path().join("regular.json"), "unsigned").unwrap();
    std::os::unix::fs::symlink(directory.path().join("regular.json"), &link).unwrap();
    let (finished, result) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = finished.send(read_policy(&pipe).is_err() && read_policy(&link).is_err());
    });
    assert!(result
        .recv_timeout(std::time::Duration::from_secs(3))
        .unwrap());
}
