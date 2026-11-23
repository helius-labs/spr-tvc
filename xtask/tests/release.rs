use super::*;

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
        ("deploy", "mainnet", vec!["--image", "image"]),
        ("deploy", "devnet", vec!["--source-commit", &sha]),
        ("prepare", "devnet", vec![]),
        ("pin", "devnet", vec!["--signed-policy", "signed.json"]),
        ("pin", "devnet", vec!["--image", "image"]),
        ("pin", "devnet", vec!["--run", "123"]),
        ("pin", "devnet", vec!["--publish"]),
        ("pin", "devnet", vec!["--replicas", "1"]),
        ("pin", "devnet", vec!["--activate"]),
        (
            "deploy",
            "mainnet",
            vec!["--source-commit", &sha, "--activate"],
        ),
        ("deploy", "mainnet", vec![]),
        ("deploy", "mainnet", vec!["--source-commit", &sha[..12]]),
        ("pin", "mainnet", vec!["--source-commit", &sha]),
    ] {
        assert!(
            parse(phase, network, &args).unwrap().validate().is_err(),
            "{phase} {network}"
        );
    }
    for args in [
        &[][..],
        &["--image", "image"],
        &["--run", "123"],
        &["--publish"],
        &["--activate"],
    ] {
        parse("deploy", "devnet", args).unwrap().validate().unwrap();
    }
    for args in [
        &["--run", "0"][..],
        &["--replicas", "0"],
        &["--publish", "--run", "123"],
        &["--image", "image", "--run", "123"],
        &["--image", "image", "--publish"],
    ] {
        assert!(parse("deploy", "devnet", args).is_err(), "{args:?}");
    }
    for replicas in ["1", "2"] {
        parse(
            "deploy",
            "devnet",
            &["--image", "image", "--replicas", replicas],
        )
        .unwrap()
        .validate()
        .unwrap();
    }
    parse(
        "deploy",
        "mainnet",
        &[
            "--image",
            "image",
            "--replicas",
            "2",
            "--source-commit",
            &sha,
        ],
    )
    .unwrap()
    .validate()
    .unwrap();
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
fn deployment_records_do_not_cache_turnkey_status() {
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
        tools::Credentials::profile(dir.path())
            .unwrap()
            .organization_id,
        "active-org"
    );
}
