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
fn accepts_custody_and_ledger_inspection_profiles_for_payment_activation() {
    let parsed = Args::try_parse_from([
        "nitro-sign",
        "policy.json",
        "--key",
        "fixture",
        "--public-key",
        "fixture",
        "--custody-trust",
        "trust.json",
        "--source-profile",
        "source-read",
        "--replica-profile",
        "replica-read",
        "--custody-key-profiles",
        "key-profiles.json",
    ])
    .unwrap();
    assert_eq!(parsed.source_profile.as_deref(), Some("source-read"));
    assert_eq!(parsed.replica_profile.as_deref(), Some("replica-read"));
    assert_eq!(
        parsed.custody_key_profiles.as_deref(),
        Some(Path::new("key-profiles.json"))
    );
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
        let first = scope.spawn(|| store_signed_policy(&path, "unsigned", "first", || Ok(())));
        let second = scope.spawn(|| store_signed_policy(&path, "unsigned", "second", || Ok(())));
        (first.join().unwrap(), second.join().unwrap())
    });
    assert_ne!(first.is_ok(), second.is_ok());
    let latest = read_document(&path, MAX_POLICY_BYTES).unwrap();
    assert_eq!(latest, if first.is_ok() { "first" } else { "second" });
    let stale = store_signed_policy(&path, "unsigned", "stale", || Ok(())).unwrap_err();
    assert!(
        stale.to_string().contains("policy changed during signing"),
        "unexpected signing error: {stale:#}"
    );
    store_signed_policy(&path, &latest, "both", || Ok(())).unwrap();
    assert_eq!(read_document(&path, MAX_POLICY_BYTES).unwrap(), "both");
}

#[test]
fn activation_is_requalified_after_kms_before_installing_a_signature() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.json");
    let trust = directory.path().join("trust.json");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let policy = serde_json::json!({"action": "activate", "recoveryOnly": false, "targets": [{}],
                                   "validFromMs": now.to_string(), "expiresAtMs": (now + 60_000).to_string()});
    let before = jcs_serialize(
        &serde_json::json!({"policy": policy, "signatures": [], "custodySignatures": []}),
    )
    .unwrap();
    let signer = SigningKey::from_bytes(&[1; 32].into()).unwrap();
    let arn = "arn:aws:kms:eu-west-1:000000000001:key/00000000-0000-0000-0000-000000000001";
    let signature: Signature = signer
        .sign_prehash(&digest(&policy, true).unwrap())
        .unwrap();
    let kms = serde_json::to_vec(&serde_json::json!({
        "KeyId": arn, "Signature": STANDARD.encode(signature.to_der()), "SigningAlgorithm": "ECDSA_SHA_256"
    })).unwrap();
    let public = encode_lower_hex(signer.verifying_key().to_sec1_point(false).as_bytes());
    for failure in [
        Some("roster rotated"),
        Some("qualification changed"),
        Some("trust changed"),
        None,
    ] {
        std::fs::write(&path, &before).unwrap();
        std::fs::write(&trust, "{}").unwrap();
        let args = Args {
            policy: path.clone(),
            key: arn.to_owned(),
            public_key: public.clone(),
            custody_trust: trust.clone(),
            source_profile: None,
            replica_profile: None,
            custody_key_profiles: None,
            custody: true,
        };
        let mut checks = 0;
        let result = sign_with_capture(args, |command| {
            match command.get_program().to_str().unwrap() {
                "python3" => {
                    let args: Vec<_> = command.get_args().collect();
                    assert_ne!(Path::new(args[2]), trust);
                    assert_eq!(std::fs::read_to_string(args[2]).unwrap(), "{}");
                    assert_eq!(std::fs::read_to_string(args[4]).unwrap(), before);
                    checks += 1;
                    if checks == 2 {
                        match failure {
                            Some("roster rotated") => {
                                anyhow::bail!("custody approval roster rotated")
                            }
                            Some("qualification changed") => {
                                return Ok(
                                    br#"{"nextCutover":null,"canaryDigest":"different"}"#.to_vec()
                                )
                            }
                            _ => {}
                        }
                    }
                    Ok(br#"{"nextCutover":null,"canaryDigest":"initial"}"#.to_vec())
                }
                "aws" => {
                    assert_eq!(checks, 1);
                    if failure == Some("trust changed") {
                        std::fs::write(&trust, "{\"changed\":true}").unwrap();
                    }
                    Ok(kms.clone())
                }
                _ => unreachable!(),
            }
        });
        assert_eq!(checks, 2);
        let saved = read_document(&path, MAX_POLICY_BYTES).unwrap();
        if let Some(reason) = failure {
            assert!(result.unwrap_err().to_string().contains(reason));
            assert_eq!(saved, before);
        } else {
            result.unwrap();
            let signed: SignedPolicy = serde_json::from_str(&saved).unwrap();
            assert_eq!(signed.policy, policy);
            assert_eq!(signed.custody_signatures.len(), 1);
            assert_eq!(signed.custody_signatures[0].key, public);
        }
    }
}

#[test]
fn expired_policy_or_custody_roster_closes_the_signing_window() {
    use serde_json::json;
    assert!(require_signing_window(u64::MAX, &json!({"nextCutover":null})).is_ok());
    assert!(require_signing_window(u64::MAX, &serde_json::Value::Null).is_ok());
    assert!(
        require_signing_window(u64::MAX, &json!({"nextCutover":"1"}))
            .unwrap_err()
            .to_string()
            .contains("roster rotated")
    );
    assert!(require_signing_window(1, &serde_json::Value::Null)
        .unwrap_err()
        .to_string()
        .contains("policy expired"));
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
        let _ = finished.send(
            read_document(&pipe, MAX_POLICY_BYTES).is_err()
                && read_document(&link, MAX_POLICY_BYTES).is_err(),
        );
    });
    assert!(result
        .recv_timeout(std::time::Duration::from_secs(3))
        .unwrap());
}
