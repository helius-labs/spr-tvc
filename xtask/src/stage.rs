use std::process::Command;

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use spr_tvc_wire::types::{Network, ServiceInfo};

use crate::tools::{bridge, capture, capture_check, run, tvc, tvc_json, Credentials};
use crate::{lower_hex, read_json, write_json, Release, APP};

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

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Deployment {
    pub(crate) deploy_id: String,
}

pub(crate) fn image_digest<'a>(
    image: &'a str,
    repository: &str,
    network: Network,
    source_commit: Option<&str>,
) -> Result<&'a str> {
    let (tag, digest) = image
        .split_once("@sha256:")
        .context("image needs an immutable SHA-256 digest")?;
    let prefix = format!("{repository}:{APP}-{network}-");
    let suffix = tag
        .strip_prefix(&prefix)
        .context("image must have the release network tag")?;
    ensure!(
        lower_hex(digest, 64) && lower_hex(suffix, 12),
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

pub(crate) fn require_candidate(live: Option<&str>, recorded: Option<&str>) -> Result<()> {
    ensure!(
        live.is_none() || live == recorded,
        "stage mainnet releases in a separate Turnkey app"
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

    pub(crate) fn describe(&self) -> Result<()> {
        let image = self
            .args
            .image
            .as_deref()
            .context("describe requires --image")?;
        ensure!(
            !self.path("deploy").try_exists()?,
            "use a new release ID for a staged deployment"
        );
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
        write_json(
            &self.path("deployment"),
            &self.deployment_descriptor(image, digest),
        )
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

    pub(crate) fn read_descriptor(&self) -> Result<Descriptor> {
        let descriptor: Descriptor =
            read_json(&self.path("deployment")).context("run describe first")?;
        ensure!(
            lower_hex(&descriptor.expected_pivot_digest, 64)
                && descriptor
                    == self.deployment_descriptor(
                        &descriptor.pivot_container_image_url,
                        &descriptor.expected_pivot_digest
                    ),
            "deployment descriptor does not match the release config"
        );
        self.verify_image(&descriptor.pivot_container_image_url)?;
        Ok(descriptor)
    }

    pub(crate) fn live_deployment(&self) -> Result<Option<String>> {
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
            .find(|app| app.id == self.app.app_id)
            .context("configured app is absent from the active TVC organization")?
            .live_deployment_id
            .filter(|id| !id.is_empty()))
    }

    pub(crate) fn live_info(&self) -> Result<ServiceInfo> {
        let output = capture_check(&mut bridge(&["info", &self.app.endpoint]))?;
        serde_json::from_slice(&output).context("decode live discovery")
    }

    pub(crate) fn stage(&self) -> Result<()> {
        let descriptor = self.read_descriptor()?;
        let credentials = Credentials::load()?;
        let path = self.path("deploy");
        let existing: Option<Deployment> = if path.try_exists()? {
            Some(read_json(&path)?)
        } else {
            None
        };
        let live = self.live_deployment()?;
        if self.network() == Network::Mainnet {
            self.production_trust()?;
            require_candidate(
                live.as_deref(),
                existing.as_ref().map(|record| record.deploy_id.as_str()),
            )?;
        }
        let record = if let Some(record) = existing {
            record
        } else {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct CreatedDeployment {
                deployment_id: String,
            }
            let created: CreatedDeployment = tvc_json(
                tvc(&["deploy", "create", "--config-file"]).arg(self.path("deployment")),
                capture,
            )?;
            let record = Deployment {
                deploy_id: created.deployment_id,
            };
            write_json(&path, &record)?;
            record
        };
        self.approved_deployment(&record.deploy_id, &descriptor, &credentials)?;
        println!("verified deployment {}", record.deploy_id);
        if live.as_deref() != Some(&record.deploy_id) {
            println!("Review, approve, and provision it with tvc.");
        }
        Ok(())
    }
}
