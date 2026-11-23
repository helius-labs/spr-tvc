use super::*;
use clap::Parser;

#[test]
fn image_tag_and_digest_are_bound_to_network_and_reviewed_commit() {
    let repo = "ghcr.io/helius-labs/spr-tvc-decryption-service";
    let commit = "a".repeat(40);
    let digest = "b".repeat(64);
    let tag = format!("{repo}:decryption-service-mainnet-{}", &commit[..12]);
    let image = format!("{tag}@sha256:{digest}");
    assert_eq!(
        image_digest(&image, repo, Network::Mainnet, Some(&commit)).unwrap(),
        digest
    );
    for (invalid, network, sha) in [
        (tag, Network::Mainnet, &commit),
        (image.clone(), Network::Mainnet, &"b".repeat(40)),
        (image.clone(), Network::Devnet, &commit),
    ] {
        assert!(image_digest(&invalid, repo, network, Some(sha)).is_err());
    }
    let command = provenance_command(repo, &digest, &commit);
    assert_eq!(command.get_program(), "gh");
    assert!(command.get_args().eq([
        "attestation",
        "verify",
        &format!("oci://{repo}@sha256:{digest}"),
        "--repo",
        "helius-labs/spr-tvc",
        "--cert-identity",
        "https://github.com/helius-labs/spr-tvc/.github/workflows/publish-enclave-image.yml@refs/heads/main",
        "--source-ref",
        "refs/heads/main",
        "--source-digest",
        &commit,
        "--signer-digest",
        &commit,
        "--deny-self-hosted-runners",
        "--predicate-type",
        "https://slsa.dev/provenance/v1",
    ]));
}

#[test]
fn staging_can_resume_its_candidate_but_cannot_replace_the_live_deployment() {
    require_candidate(None, None).unwrap();
    require_candidate(Some("candidate"), Some("candidate")).unwrap();
    assert!(require_candidate(Some("live"), Some("candidate")).is_err());
    assert!(require_candidate(Some("live"), None).is_err());
}

#[test]
fn staging_copies_the_checked_descriptor_before_invoking_turnkey() {
    let config = serde_json::from_str(include_str!("../../enclave/deploy/release.json")).unwrap();
    let args = crate::Args::parse_from(["xtask", "stage", "candidate", "--network", "devnet"]);
    let release = Release {
        args: &args,
        config: &config,
        app: &config.networks.devnet,
    };
    let descriptor = release.deployment_descriptor("image", &"a".repeat(64));
    let mut original = tempfile::NamedTempFile::new().unwrap();
    serde_json::to_writer(&mut original, &descriptor).unwrap();
    let checked: Descriptor = read_json(original.path()).unwrap();
    let approved_input = copy_descriptor(&checked).unwrap();
    let command = tvc_create(approved_input.path(), []);
    std::fs::write(original.path(), r#"{"dangerousDeployDebugMode":true}"#).unwrap();
    assert_eq!(
        command.get_args().last(),
        Some(approved_input.path().as_os_str())
    );
    let submitted: Descriptor = read_json(approved_input.path()).unwrap();
    assert!(submitted == descriptor);
}

fn attempt() -> StageAttempt {
    StageAttempt {
        organization_id: "organization".into(),
        descriptor_sha256: "a".repeat(64),
    }
}

#[test]
fn an_interrupted_create_can_only_resume_with_a_verified_deployment_id() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("candidate.deploy.json");
    let never_create = || panic!("stage submitted a second create");
    let never_verify = |_: &str| panic!("stage verified an unknown candidate");
    let error = stage_deployment(
        &path,
        attempt(),
        None,
        |_| Ok(()),
        || {
            let pending: StageRecord = read_json(&path).unwrap();
            assert!(matches!(pending, StageRecord::Pending(record) if record == attempt()));
            anyhow::bail!("lost response after submission")
        },
        never_verify,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("lost response after submission"));

    let error = stage_deployment(
        &path,
        attempt(),
        None,
        |_| Ok(()),
        never_create,
        never_verify,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("stage outcome is unknown"));

    for altered in [
        StageAttempt {
            organization_id: "other".into(),
            ..attempt()
        },
        StageAttempt {
            descriptor_sha256: "b".repeat(64),
            ..attempt()
        },
    ] {
        let error = stage_deployment(
            &path,
            altered,
            Some("candidate"),
            |_| Ok(()),
            never_create,
            never_verify,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("different descriptor or organization"));
    }

    assert!(stage_deployment(
        &path,
        attempt(),
        Some("wrong"),
        |_| Ok(()),
        never_create,
        |_| anyhow::bail!("deployment did not match the approved input"),
    )
    .is_err());
    assert!(matches!(
        read_json::<StageRecord>(&path).unwrap(),
        StageRecord::Pending(_)
    ));

    let saved = stage_deployment(
        &path,
        attempt(),
        Some("candidate"),
        |candidate| require_candidate(Some("candidate"), candidate),
        never_create,
        |id| {
            assert_eq!(id, "candidate");
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(saved, "candidate");
    assert_eq!(
        read_json::<Deployment>(&path).unwrap().deploy_id,
        "candidate"
    );
    let error = stage_deployment(
        &path,
        attempt(),
        Some("other"),
        |_| Ok(()),
        never_create,
        never_verify,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("already records a different deployment ID"));
}

#[test]
fn a_confirmed_create_survives_a_verification_failure_and_serializes_staging() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("candidate.deploy.json");
    let never_create = || panic!("stage submitted a second create");
    let error = stage_deployment(
        &path,
        attempt(),
        None,
        |_| Ok(()),
        || {
            let concurrent =
                stage_deployment(&path, attempt(), None, |_| Ok(()), never_create, |_| Ok(()))
                    .unwrap_err();
            assert!(format!("{concurrent:#}").contains("another process is staging this release"));
            Ok("candidate".into())
        },
        |_| anyhow::bail!("verification outage"),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("verification outage"));
    assert_eq!(
        read_json::<Deployment>(&path).unwrap().deploy_id,
        "candidate"
    );
    let saved = stage_deployment(
        &path,
        attempt(),
        None,
        |candidate| require_candidate(Some("candidate"), candidate),
        never_create,
        |id| {
            assert_eq!(id, "candidate");
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(saved, "candidate");
}
