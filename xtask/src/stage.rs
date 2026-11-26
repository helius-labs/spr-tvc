use std::io::Write;
use std::process::Command;

use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use spr_tvc_wire::types::{Network, ServiceInfo};

use crate::tools::{bridge, capture, capture_check, run, tvc, tvc_json, Credentials};
use crate::{lower_hex, Release, APP};

const PIVOT_PATH: &str = "/tvc_app";

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Descriptor {
    app_id: String,
    qos_version: String,
    pub(crate) pivot_container_image_url: String,
    pivot_path: String,
    pub(crate) pivot_args: Vec<String>,
    pub(crate) expected_pivot_digest: String,
    dangerous_deploy_debug_mode: bool,
    health_check_type: String,
    health_check_port: u16,
    public_ingress_port: u16,
}

pub(crate) struct ResolvedImage {
    pub(crate) image: String,
    pub(crate) source_commit: Option<String>,
}

pub(crate) fn image_digest<'a>(
    image: &'a str,
    repository: &str,
    network: Network,
    source_commit: Option<&str>,
) -> Result<&'a str> {
    let digest = image
        .split_once("@sha256:")
        .map(|(_, digest)| digest)
        .context("image needs an immutable SHA-256 digest")?;
    let suffix = release_label(image, repository, network)?;
    ensure!(
        lower_hex(digest, 64),
        "image needs a release commit tag and a lowercase SHA-256 digest"
    );
    if let Some(commit) = source_commit {
        ensure!(
            lower_hex(commit, 40) && suffix == &commit[..12],
            "image tag must name the reviewed source commit"
        );
    }
    Ok(digest)
}

pub(crate) fn release_label<'a>(
    image: &'a str,
    repository: &str,
    network: Network,
) -> Result<&'a str> {
    let tag = image
        .split_once("@sha256:")
        .map(|(tag, _)| tag)
        .context("image needs an immutable SHA-256 digest")?;
    let prefix = format!("{repository}:{APP}-{network}-");
    let suffix = tag
        .strip_prefix(&prefix)
        .context("image must have the release network tag")?;
    ensure!(
        lower_hex(suffix, 12),
        "image needs a release commit tag and a lowercase SHA-256 digest"
    );
    Ok(suffix)
}

/// A digest-only Turnkey reference becomes the published tag. Mainnet learns the
/// commit from the image attestation. A tagged reference is kept as published.
pub(crate) fn image_reference(
    url: &str,
    repository: &str,
    network: Network,
) -> Result<ResolvedImage> {
    let (tag, digest) = url
        .split_once("@sha256:")
        .context("deployment image needs an immutable SHA-256 digest")?;
    ensure!(
        lower_hex(digest, 64),
        "deployment image digest is not lowercase SHA-256"
    );
    if tag == repository {
        ensure!(
            network == Network::Mainnet,
            "pass --image for this devnet deployment"
        );
        let source_commit = attested_source_commit(repository, digest)?;
        return Ok(ResolvedImage {
            image: format!(
                "{repository}:{APP}-{network}-{}@sha256:{digest}",
                &source_commit[..12]
            ),
            source_commit: Some(source_commit),
        });
    }
    Ok(ResolvedImage {
        image: url.to_owned(),
        source_commit: None,
    })
}

pub(crate) fn require_candidate(live: Option<&str>, recorded: Option<&str>) -> Result<()> {
    ensure!(
        live.is_none() || live == recorded,
        "deploy mainnet releases in a separate Turnkey app"
    );
    Ok(())
}

pub(crate) fn provenance_command(repository: &str, digest: &str, commit: &str) -> Command {
    let mut command = Command::new("gh");
    command.args([
        "attestation",
        "verify",
        &format!("oci://{repository}@sha256:{digest}"),
        "--repo",
        "helius-labs/spr-tvc",
        "--signer-workflow",
        "helius-labs/spr-tvc/.github/workflows/publish-enclave-image.yml",
        "--source-ref",
        "refs/heads/main",
        "--source-digest",
        commit,
        "--predicate-type",
        "https://slsa.dev/provenance/v1",
    ]);
    command
}

fn attestation_command(repository: &str, digest: &str) -> Command {
    let mut command = Command::new("gh");
    command.args([
        "attestation",
        "verify",
        &format!("oci://{repository}@sha256:{digest}"),
        "--repo",
        "helius-labs/spr-tvc",
        "--signer-workflow",
        "helius-labs/spr-tvc/.github/workflows/publish-enclave-image.yml",
        "--source-ref",
        "refs/heads/main",
        "--predicate-type",
        "https://slsa.dev/provenance/v1",
        "--format",
        "json",
    ]);
    command
}

pub(crate) fn attested_source_commit(repository: &str, digest: &str) -> Result<String> {
    let output = capture_check(&mut attestation_command(repository, digest))?;
    source_commit_from_attestation(&output)
}

pub(crate) fn source_commit_from_attestation(json: &[u8]) -> Result<String> {
    let value: Value = serde_json::from_slice(json).context("decode attestation")?;
    let bundles = attestation_bundles(&value)?;
    ensure!(!bundles.is_empty(), "attestation response was empty");
    let mut commits = Vec::new();
    for bundle in bundles {
        let payload = bundle
            .pointer("/bundle/dsseEnvelope/payload")
            .or_else(|| bundle.pointer("/dsseEnvelope/payload"))
            .and_then(Value::as_str)
            .context("attestation bundle has no DSSE payload")?;
        let bytes = STANDARD
            .decode(payload)
            .context("decode attestation payload")?;
        let statement: Value =
            serde_json::from_slice(&bytes).context("decode attestation statement")?;
        let dependencies = statement
            .pointer("/predicate/buildDefinition/resolvedDependencies")
            .and_then(Value::as_array)
            .context("attestation has no source dependencies")?;
        for dependency in dependencies {
            if let Some(commit) = dependency
                .pointer("/digest/gitCommit")
                .and_then(Value::as_str)
                .filter(|commit| lower_hex(commit, 40))
            {
                commits.push(commit.to_owned());
            }
        }
    }
    commits.sort();
    commits.dedup();
    ensure!(
        commits.len() == 1,
        "attestation must name one source commit"
    );
    Ok(commits.remove(0))
}

fn attestation_bundles(value: &Value) -> Result<Vec<&Value>> {
    if let Some(list) = value.as_array() {
        return Ok(list.iter().collect());
    }
    if let Some(list) = value.get("attestations").and_then(Value::as_array) {
        return Ok(list.iter().collect());
    }
    if value.get("bundle").is_some() || value.get("dsseEnvelope").is_some() {
        return Ok(vec![value]);
    }
    anyhow::bail!("unexpected attestation response")
}

impl Release<'_> {
    fn verify_image(&self, image: &str) -> Result<()> {
        let repository = &self.config.image_repository;
        let commit = self.args.source_commit.as_deref();
        let digest = image_digest(image, repository, self.network(), commit)?;
        if let Some(commit) = commit {
            run(&mut provenance_command(repository, digest, commit))?;
        }
        Ok(())
    }

    pub(crate) fn measured_descriptor(&self) -> Result<Descriptor> {
        let image = &self.args.image;
        self.verify_image(image)?;
        let output = capture(Command::new("docker").args([
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--platform",
            "linux/amd64",
            "--entrypoint",
            "sha256sum",
            image,
            PIVOT_PATH,
        ]))?;
        let digest = std::str::from_utf8(&output)?
            .split_ascii_whitespace()
            .next()
            .filter(|digest| lower_hex(digest, 64))
            .context("could not read /tvc_app SHA-256")?;
        Ok(self.deployment_descriptor(image, digest))
    }

    pub(crate) fn deployment_descriptor(&self, image: &str, digest: &str) -> Descriptor {
        Descriptor {
            app_id: self.app.app_id.clone(),
            qos_version: self.qos_version().into(),
            pivot_container_image_url: image.into(),
            pivot_path: PIVOT_PATH.into(),
            pivot_args: [
                "--host",
                "0.0.0.0",
                "--port",
                "3000",
                "--security-domain-id",
                &hex::encode(self.app.security_domain_id),
                "--release-id",
                &self.args.release_id,
                "--quorum-key-id",
                &self.app.quorum_key_id,
                "--quorum-key-epoch",
                &self.app.quorum_key_epoch.to_string(),
            ]
            .map(str::to_owned)
            .into(),
            expected_pivot_digest: digest.into(),
            dangerous_deploy_debug_mode: false,
            health_check_type: "TVC_HEALTH_CHECK_TYPE_HTTP".into(),
            health_check_port: 3000,
            public_ingress_port: 3000,
        }
    }

    pub(crate) fn live_deployment(&self) -> Result<Option<String>> {
        live_deployment_id(&self.app.app_id)
    }

    pub(crate) fn live_info(&self) -> Result<ServiceInfo> {
        let output = capture_check(&mut bridge(&["info", &self.app.endpoint]))?;
        serde_json::from_slice(&output).context("decode live discovery")
    }

    pub(crate) fn deploy(&self) -> Result<()> {
        let descriptor = self.measured_descriptor()?;
        let credentials = Credentials::load()?;
        let live = self.live_deployment()?;
        if self.network() == Network::Mainnet {
            self.production_trust()?;
            require_candidate(live.as_deref(), self.args.deploy_id.as_deref())?;
        }
        let deploy_id = if let Some(id) = &self.args.deploy_id {
            ensure!(!id.is_empty(), "deploy id is empty");
            id.clone()
        } else {
            let mut config = tempfile::NamedTempFile::new()?;
            serde_json::to_writer_pretty(&mut config, &descriptor)?;
            writeln!(config)?;
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct CreatedDeployment {
                deployment_id: String,
            }
            let created: CreatedDeployment = tvc_json(
                tvc(&["deploy", "create", "--config-file"]).arg(config.path()),
                capture,
            )?;
            created.deployment_id
        };
        println!("deploy_id={deploy_id}");
        self.approved_deployment(&deploy_id, &descriptor, &credentials)?;
        println!("verified deployment {deploy_id}");
        if live.as_deref() != Some(deploy_id.as_str()) {
            println!(
                "Operators approve the manifest and provision shares with tvc. Pin {deploy_id} after it is live."
            );
        }
        Ok(())
    }
}

pub(crate) fn live_deployment_id(app_id: &str) -> Result<Option<String>> {
    #[derive(Deserialize)]
    struct Apps {
        apps: Vec<App>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct App {
        id: String,
        live_deployment_id: Option<String>,
    }
    let apps: Apps = tvc_json(&mut tvc(&["app", "list"]), capture_check)?;
    Ok(apps
        .apps
        .into_iter()
        .find(|app| app.id == app_id)
        .context("configured app is absent from the active TVC organization")?
        .live_deployment_id
        .filter(|id| !id.is_empty()))
}
