use super::*;

#[test]
fn production_requires_independent_operator_phases_and_full_provenance() {
    let mainnet = |phase: &str, extra: &[&str]| {
        Args::try_parse_from(
            ["xtask", phase, "candidate", "--network", "mainnet"]
                .into_iter()
                .chain(extra.iter().copied()),
        )
        .unwrap()
    };
    let sha = "1".repeat(40);
    for (phase, extra) in [
        ("all", vec!["--source-commit", &sha]),
        ("deploy", vec!["--source-commit", &sha, "--unattended"]),
        (
            "deploy",
            vec!["--source-commit", &sha, "--prune-deployments"],
        ),
        (
            "deploy",
            vec![
                "--source-commit",
                &sha,
                "--operator-seeds",
                "seeds",
                "--quorum-key-metadata",
                "shares",
            ],
        ),
        ("deploy", vec!["--source-commit", &sha[..12]]),
        ("policy", vec!["--source-commit", &sha]),
    ] {
        assert!(mainnet(phase, &extra).validate().is_err());
    }
    mainnet("build", &["--source-commit", &sha])
        .validate()
        .unwrap();
    mainnet(
        "policy",
        &["--source-commit", &sha, "--signed-policy", "signed.json"],
    )
    .validate()
    .unwrap();
    assert!(release_id("../candidate").is_err());
}

#[test]
fn tracked_devnet_config_and_records_use_the_operator_schema() {
    let config: ReleaseConfig =
        serde_json::from_str(include_str!("../../enclave/deploy/release.json")).unwrap();
    assert!(!config.networks.devnet.app_id.is_empty());
    assert!(!config.networks.devnet.operator_ids.is_empty());
    let app: AppConfig = serde_json::from_str(include_str!(
        "../../enclave/deploy/devnet/spr-decryption-service-devnet.app.json"
    ))
    .unwrap();
    assert_eq!(app.quorum_public_key.len(), 130);
    let record: deploy::Deployment = serde_json::from_str(include_str!(
        "../../enclave/deploy/devnet/decryption-service-decryption-service-devnet-2cf18b375f57.deploy.json"
    )).unwrap();
    assert!(record.live);
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
