use std::num::NonZeroU32;
use std::path::Path;
use std::process::Command;

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use spr_tvc_protocol::types::{Network, ServiceInfo};

use crate::publish::{self, REPO, WORKFLOW};
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) replicas: Option<NonZeroU32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) hosted_share_receipts: Vec<String>,
}

impl Deployment {
    fn check_replicas(&self, requested: Option<NonZeroU32>) -> Result<()> {
        ensure!(
            requested.is_none() || requested == self.replicas,
            "deployment already exists with a different replica request; use a new release ID"
        );
        Ok(())
    }
}

fn create_command(descriptor: &Path, replicas: Option<NonZeroU32>) -> Command {
    let mut command = tvc(&["deploy", "create", "--non-interactive", "--config-file"]);
    command.arg(descriptor);
    // The TVC CLI gives environment overrides precedence over the descriptor.
    for name in [
        "TVC_APP_ID",
        "TVC_QOS_VERSION",
        "TVC_PIVOT_IMAGE_URL",
        "TVC_EXPECTED_PIVOT_DIGEST",
        "TVC_PIVOT_PATH",
        "TVC_PIVOT_ARGS",
        "TVC_PIVOT_PULL_SECRET",
        "TVC_DANGEROUS_DEPLOY_DEBUG_MODE",
        "TVC_HEALTH_CHECK_PORT",
        "TVC_PUBLIC_INGRESS_PORT",
        "TVC_REPLICAS",
    ] {
        command.env_remove(name);
    }
    if let Some(replicas) = replicas {
        command.args(["--replicas", &replicas.to_string()]);
    }
    command
}

fn image_digest<'a>(
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

fn require_candidate(live: Option<&str>, recorded: Option<&str>) -> Result<()> {
    ensure!(
        live.is_none() || live == recorded,
        "stage mainnet releases in a separate Turnkey app"
    );
    Ok(())
}

fn provenance_command(repository: &str, digest: &str, commit: &str) -> Command {
    let mut command = Command::new("gh");
    command.args([
        "attestation",
        "verify",
        &format!("oci://{repository}@sha256:{digest}"),
        "--repo",
        REPO,
        "--signer-workflow",
        &format!("{REPO}/{WORKFLOW}"),
        "--source-ref",
        "refs/heads/main",
        "--source-digest",
        commit,
        "--predicate-type",
        "https://slsa.dev/provenance/v1",
    ]);
    command
}

fn pivot_digest(image: &str) -> Result<String> {
    let rootfs = tempfile::NamedTempFile::new()?;
    run(Command::new("crane")
        .args(["export", "--platform", "linux/amd64", image, "-"])
        .stdout(rootfs.reopen()?))
    .context("export the pinned image with crane; see the release runbook for setup")?;
    let output = capture_check(
        Command::new("bash")
            .args([
                "-o",
                "pipefail",
                "-c",
                "tar -xOf \"$1\" \"$2\" | sha256sum",
                "pivot-digest",
            ])
            .arg(rootfs.path())
            .arg(PIVOT_PATH.trim_start_matches('/')),
    )?;
    let digest = std::str::from_utf8(&output)?
        .split_ascii_whitespace()
        .next()
        .filter(|digest| lower_hex(digest, 64))
        .context("could not read /tvc_app SHA-256")?;
    Ok(digest.to_owned())
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

    fn describe(&self, image: &str) -> Result<Descriptor> {
        self.verify_image(image)?;
        let descriptor = self.deployment_descriptor(image, &pivot_digest(image)?);
        write_json(&self.path("deployment"), &descriptor)?;
        Ok(descriptor)
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
        let mut command = bridge(&["info", &self.app.endpoint]);
        if self.args.activate {
            command.arg("--wait");
        }
        let output = capture_check(&mut command)?;
        serde_json::from_slice(&output).context("decode live discovery")
    }

    fn selected_image(&self) -> Result<Option<String>> {
        let run = if self.args.publish {
            Some(publish::publish(self.network())?)
        } else {
            self.args.run
        };
        let Some(run) = run else {
            return Ok(self.args.image.clone());
        };
        let (image, commit) = publish::image_from_run(run)?;
        image_digest(
            &image,
            &self.config.image_repository,
            self.network(),
            Some(&commit),
        )?;
        Ok(Some(image))
    }

    pub(crate) fn deploy(&self) -> Result<()> {
        let path = self.path("deploy");
        let existing: Option<Deployment> =
            path.try_exists()?.then(|| read_json(&path)).transpose()?;
        let described = self.path("deployment").try_exists()?;
        ensure!(
            !self.args.publish || (!described && existing.is_none()),
            "release already has a candidate; rerun without --publish"
        );
        ensure!(
            described
                || existing.is_some()
                || self.args.publish
                || self.args.run.is_some()
                || self.args.image.is_some(),
            "a new deployment needs --run, --publish, or --image"
        );
        if let Some(record) = &existing {
            record.check_replicas(self.args.replicas)?;
        }
        let credentials = Credentials::load()?;
        let live = self.live_deployment()?;
        if self.args.activate {
            ensure!(
                live.is_none()
                    || live.as_deref() == existing.as_ref().map(|record| record.deploy_id.as_str()),
                "--activate requires a fresh devnet app or its already live deployment"
            );
        }
        if self.network() == Network::Mainnet {
            self.production_trust()?;
            require_candidate(
                live.as_deref(),
                existing.as_ref().map(|record| record.deploy_id.as_str()),
            )?;
        }
        let image = self.selected_image()?;
        let descriptor = if described || existing.is_some() {
            let descriptor = self.read_descriptor()?;
            ensure!(
                image.is_none_or(|image| descriptor.pivot_container_image_url == image),
                "release already describes a different image; use a new release ID"
            );
            descriptor
        } else {
            self.describe(image.as_deref().context("missing release image")?)?
        };
        let mut record = if let Some(record) = existing {
            record
        } else {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct CreatedDeployment {
                deployment_id: String,
            }
            let created: CreatedDeployment = tvc_json(
                &mut create_command(&self.path("deployment"), self.args.replicas),
                capture,
            )?;
            let record = Deployment {
                deploy_id: created.deployment_id,
                replicas: self.args.replicas,
                hosted_share_receipts: Vec::new(),
            };
            write_json(&path, &record)?;
            record
        };
        self.approved_deployment(&record.deploy_id, &descriptor, &credentials)?;
        println!("verified deployment {}", record.deploy_id);
        if self.args.activate {
            self.activate(&mut record, &credentials)?;
            self.policy()?;
        } else if live.as_deref() != Some(&record.deploy_id) {
            println!("Review, approve, and provision it with tvc.");
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/stage.rs"]
mod tests;
