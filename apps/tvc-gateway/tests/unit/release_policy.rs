use spr_tvc_protocol::release::{ReleaseAuthorityKey, sign_release_policy};
use spr_tvc_protocol::{ReleaseAuthoritySignature, SignedReleasePolicy};

use super::tests::{TEST_SECRET, test_policy};
use super::*;

const AUTHORITY_SECRET: [u8; 32] = [8; 32];

/// A release file for `policy`, signed by a test authority, with the PCRs
/// clients read, written where only this test reads it.
fn release_file(name: &str, policy: ReleasePolicy) -> std::path::PathBuf {
    let signature = sign_release_policy(&policy, &AUTHORITY_SECRET).expect("signs");
    let public_key = crate::config::public_key_of(&AUTHORITY_SECRET).expect("valid key");
    let file = serde_json::json!({
        "releasePolicy": SignedReleasePolicy {
            policy,
            authority_set_id: "test-set".to_owned(),
            signatures: vec![ReleaseAuthoritySignature {
                key_id: "test-authority".to_owned(),
                signature: signature.to_vec(),
            }],
        },
        "releaseAuthorities": PinnedReleaseAuthorities {
            authority_set_id: "test-set".to_owned(),
            threshold: 1,
            keys: vec![ReleaseAuthorityKey {
                key_id: "test-authority".to_owned(),
                public_key: public_key.to_vec(),
            }],
            minimum_revocation_epoch: 0,
        },
        "qosIdentityPcrs": { "0": "00" },
    });
    let path = std::env::temp_dir().join(format!(
        "tvc-gateway-release-{}-{name}.json",
        std::process::id()
    ));
    fs::write(&path, file.to_string()).expect("the release file writes");
    path
}

fn provisioner(path: std::path::PathBuf, network: Network) -> anyhow::Result<Provisioner> {
    let config = ProvisioningConfig {
        private_key: hex::encode(TEST_SECRET),
        expected_public_key: hex::encode(
            crate::config::public_key_of(&TEST_SECRET).expect("valid key"),
        ),
        release_path: path,
        descriptor_ttl_secs: 86_400,
    };
    Provisioner::new(&config, network)
}

#[test]
fn a_release_file_for_the_gateways_network_starts_it() {
    let path = release_file("devnet", test_policy());
    let started = provisioner(path.clone(), Network::Devnet);
    let refused = provisioner(path.clone(), Network::Mainnet);
    let _ = fs::remove_file(path);
    assert!(started.is_ok(), "{:?}", started.err());
    let error = refused
        .err()
        .expect("a devnet release starts a mainnet gateway");
    assert!(
        error
            .to_string()
            .ends_with("is the devnet release, and this gateway serves mainnet"),
        "{error}"
    );
}

#[test]
fn an_expired_or_unsigned_release_does_not_start() {
    let expired = ReleasePolicy {
        valid_from_ms: 1,
        expires_at_ms: 2,
        ..test_policy()
    };
    let path = release_file("expired", expired);
    let error = provisioner(path.clone(), Network::Devnet).err();
    let _ = fs::remove_file(path);
    let error = error.expect("an expired release starts the gateway");
    assert!(
        error
            .to_string()
            .ends_with("valid from 1 to 2 (Unix ms), not now"),
        "{error}"
    );

    let path = release_file("tampered", test_policy());
    let tampered = fs::read_to_string(&path)
        .expect("the release file reads")
        .replace("\"releaseId\":\"test\"", "\"releaseId\":\"other\"");
    fs::write(&path, tampered).expect("the release file writes");
    let error = provisioner(path.clone(), Network::Devnet).err();
    let _ = fs::remove_file(path);
    let error = error.expect("a tampered release starts the gateway");
    assert!(
        error
            .to_string()
            .ends_with("does not verify: InvalidSignature"),
        "{error}"
    );
}

#[test]
fn a_release_file_that_pins_nothing_does_not_start() {
    let path = std::env::temp_dir().join(format!(
        "tvc-gateway-release-{}-null.json",
        std::process::id()
    ));
    fs::write(&path, "null\n").expect("the release file writes");
    let error = provisioner(path.clone(), Network::Mainnet).err();
    let _ = fs::remove_file(path);
    let error = error.expect("a null release file starts the gateway");
    assert!(
        error
            .to_string()
            .contains("pins no mainnet release (it is null)"),
        "{error}"
    );
}

/// Every release file the client and this gateway's image carry
/// (`packages/tvc-wallet/src/releases/<network>.json`) is `null` or a
/// release of the network it is named after, signed by the authorities
/// it pins and in force now, with the four PCRs clients check.
#[test]
fn every_committed_release_file_pins_nothing_or_verifies_for_its_network() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packages/tvc-wallet/src/releases");
    let mut names = Vec::new();
    for entry in fs::read_dir(&dir).expect("the releases directory reads") {
        let path = entry.expect("the entry reads").path();
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("a file name")
            .to_owned();
        assert_eq!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("json"),
            "{}",
            path.display()
        );
        let network: Network = serde_json::from_value(serde_json::json!(stem))
            .unwrap_or_else(|_| panic!("{} is not named after a network", path.display()));
        let file: serde_json::Value = read_json(&path).expect("the release file parses");
        if !file.is_null() {
            let policy = read_release(&path, network, now_ms().expect("clock"))
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(policy.network, network);
            let pcrs = file["qosIdentityPcrs"]
                .as_object()
                .expect("the release file pins PCRs");
            assert_eq!(
                pcrs.keys().map(String::as_str).collect::<Vec<_>>(),
                ["0", "1", "2", "3"]
            );
            for pcr in pcrs.values() {
                let pcr = pcr.as_str().expect("a PCR is hex");
                assert!(
                    pcr.len() == 96 && pcr.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
                    "{pcr}"
                );
            }
        }
        names.push(stem);
    }
    names.sort();
    assert_eq!(names, ["devnet", "mainnet"]);
}

#[test]
fn descriptors_stop_when_the_release_expires() {
    let provisioner = super::tests::provisioner();
    let expires = test_policy().expires_at_ms;
    assert_eq!(provisioner.check_current(expires), Ok(()));
    let mut expiring = provisioner;
    expiring.policy.expires_at_ms = 10;
    assert_eq!(expiring.check_current(10), Ok(()));
    assert_eq!(expiring.check_current(11), Err(ApiError::ReleaseExpired));
}
