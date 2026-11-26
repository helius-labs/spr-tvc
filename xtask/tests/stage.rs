use spr_tvc_wire::types::Network;

use base64::{engine::general_purpose::STANDARD, Engine};

use crate::stage::{
    image_digest, provenance_command, release_label, require_candidate,
    source_commit_from_attestation,
};

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
        "--signer-workflow",
        "helius-labs/spr-tvc/.github/workflows/publish-enclave-image.yml",
        "--source-ref",
        "refs/heads/main",
        "--source-digest",
        &commit,
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
fn the_release_label_is_the_image_commit_suffix() {
    let repo = "ghcr.io/helius-labs/spr-tvc-decryption-service";
    let image = format!(
        "{repo}:decryption-service-devnet-0123456789ab@sha256:{}",
        "ab".repeat(32)
    );
    assert_eq!(
        release_label(&image, repo, Network::Devnet).unwrap(),
        "0123456789ab"
    );
    assert!(release_label(&image, repo, Network::Mainnet).is_err());
}

#[test]
fn an_attestation_names_one_source_commit() {
    let commit = "a".repeat(40);
    let statement = serde_json::json!({
        "predicate": {
            "buildDefinition": {
                "resolvedDependencies": [{
                    "uri": "git+https://github.com/helius-labs/spr-tvc@refs/heads/main",
                    "digest": { "gitCommit": commit }
                }]
            }
        }
    });
    let bundle = serde_json::json!([{
        "bundle": { "dsseEnvelope": { "payload": STANDARD.encode(serde_json::to_vec(&statement).unwrap()) } }
    }]);
    assert_eq!(
        source_commit_from_attestation(&serde_json::to_vec(&bundle).unwrap()).unwrap(),
        commit
    );
    let empty = serde_json::json!([{ "bundle": { "dsseEnvelope": { "payload": STANDARD.encode(b"{}") } } }]);
    assert!(source_commit_from_attestation(&serde_json::to_vec(&empty).unwrap()).is_err());
}
