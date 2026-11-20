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
        ("describe", "devnet", vec![]),
        ("stage", "devnet", vec!["--image", "unused"]),
        ("stage", "devnet", vec!["--source-commit", &sha]),
        ("prepare", "devnet", vec![]),
        ("pin", "devnet", vec!["--signed-policy", "signed.json"]),
        ("stage", "mainnet", vec![]),
        ("stage", "mainnet", vec!["--source-commit", &sha[..12]]),
        ("pin", "mainnet", vec!["--source-commit", &sha]),
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
fn tracked_devnet_records_match_the_current_descriptor_schema() {
    let config: ReleaseConfig =
        serde_json::from_str(include_str!("../../enclave/deploy/release.json")).unwrap();
    let app: AppConfig = serde_json::from_str(include_str!(
        "../../enclave/deploy/devnet/spr-decryption-service-devnet.app.json"
    ))
    .unwrap();
    assert_eq!(app.quorum_public_key.len(), 130);
    let id = "decryption-service-devnet-2cf18b375f57";
    let args = Args::parse_from(["xtask", "stage", id, "--network", "devnet"]);
    let release = Release {
        args: &args,
        config: &config,
        app: &config.networks.devnet,
    };
    let record: stage::Deployment = read_json(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(release.path("deploy")),
    )
    .unwrap();
    assert!(!record.deploy_id.is_empty());
    let descriptor = include_str!(
        "../../enclave/deploy/devnet/decryption-service-devnet-2cf18b375f57.deployment.json"
    );
    let tracked: stage::Descriptor = serde_json::from_str(descriptor).unwrap();
    assert!(
        tracked
            == release.deployment_descriptor(
                &tracked.pivot_container_image_url,
                &tracked.expected_pivot_digest,
            )
    );
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
