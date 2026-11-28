//! Release staging provenance, immutable image digest, and live deployment continuity tests (INV-21).

use spr_tvc_wire::types::Network;

use crate::stage::{image_digest, provenance_command, require_candidate};

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
