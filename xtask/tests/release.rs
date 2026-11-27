use std::fs;

use clap::Parser;

use crate::tools::Credentials;
use crate::{release_id, stage, Args};

#[test]
fn release_requires_inputs_for_its_phase_and_network() {
    let parse = |phase: &str, network: &str, extra: &[&str]| {
        Args::try_parse_from(
            ["xtask", phase, "candidate", "--network", network]
                .into_iter()
                .chain(extra.iter().copied()),
        )
    };
    let sha = "1".repeat(40);
    for (phase, network, args) in [
        ("describe", "devnet", vec![]),
        ("stage", "devnet", vec!["--image", "unused"]),
        ("stage", "devnet", vec!["--source-commit", &sha]),
        ("prepare", "devnet", vec![]),
        ("pin", "devnet", vec!["--signed-policy", "signed.json"]),
        ("stage", "mainnet", vec![]),
        ("stage", "mainnet", vec!["--source-commit", &sha[..12]]),
        ("pin", "mainnet", vec!["--source-commit", &sha]),
        ("stage", "devnet", vec!["--minimum-manifest-nonce", "2"]),
    ] {
        assert!(
            parse(phase, network, &args).unwrap().validate().is_err(),
            "{phase} {network}"
        );
    }
    parse("describe", "devnet", &["--image", "image"])
        .unwrap()
        .validate()
        .unwrap();
    parse("stage", "devnet", &[]).unwrap().validate().unwrap();
    parse("prepare", "mainnet", &["--source-commit", &sha])
        .unwrap()
        .validate()
        .unwrap();
    parse(
        "pin",
        "mainnet",
        &["--source-commit", &sha, "--signed-policy", "signed.json"],
    )
    .unwrap()
    .validate()
    .unwrap();
    assert!(release_id("../candidate").is_err());
}

#[test]
fn deployment_records_contain_only_the_staged_id() {
    let record: stage::Deployment = serde_json::from_str(r#"{"deployId":"candidate"}"#).unwrap();
    assert_eq!(
        serde_json::to_value(record).unwrap(),
        serde_json::json!({"deployId": "candidate"})
    );
    for field in ["approved", "provisioned", "live"] {
        let mut record = serde_json::json!({"deployId": "candidate"});
        record[field] = serde_json::Value::Null;
        assert!(serde_json::from_value::<stage::Deployment>(record).is_err());
    }
}

#[test]
fn tvc_uses_the_active_profile_and_ignores_nested_operator_ids() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("key.json");
    fs::write(&key, r#"{"public_key":"unused","private_key":"unused"}"#).unwrap();
    fs::write(
        dir.path().join("tvc.config.toml"),
        format!(
            r#"
        active_org = "active.profile"
        [orgs.inactive]
        id = "other-org"
        [orgs."active.profile"]
        id = "active-org"
        api_key_path = {:?}
        [[orgs."active.profile".operators]]
        id = "operator"
    "#,
            key.to_str().unwrap()
        ),
    )
    .unwrap();
    assert_eq!(
        Credentials::profile(dir.path()).unwrap().organization_id,
        "active-org"
    );
}
