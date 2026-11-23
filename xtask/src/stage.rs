use std::fs::{File, OpenOptions};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use spr_tvc_protocol::digest::sha256;
use spr_tvc_protocol::types::{Network, ServiceInfo};

use crate::tools::{
    bridge, capture_check, capture_with_timeout, open_regular, run, tvc, tvc_create, tvc_json,
    Credentials,
};
use crate::{lower_hex, read_json, store_json, write_json, Release, APP};

const PIVOT_PATH: &str = "/tvc_app";
const IMAGE_INSPECTION_TIMEOUT: Duration = Duration::from_secs(300);

fn copy_descriptor(descriptor: &Descriptor) -> Result<tempfile::NamedTempFile> {
    let mut file = tempfile::Builder::new().suffix(".json").tempfile()?;
    serde_json::to_writer(&mut file, descriptor)?;
    Ok(file)
}

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

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StageAttempt {
    organization_id: String,
    descriptor_sha256: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StageRecord {
    Created(Deployment),
    Pending(StageAttempt),
}

fn write_stage_record(path: &Path, record: &impl Serialize) -> Result<()> {
    store_json(path, record)?;
    File::open(path)?.sync_all()?;
    #[cfg(unix)]
    File::open(path.parent().context("missing stage directory")?)?.sync_all()?;
    Ok(())
}

fn stage_deployment(
    path: &Path,
    attempt: StageAttempt,
    recovery_id: Option<&str>,
    require_allowed: impl FnOnce(Option<&str>) -> Result<()>,
    create: impl FnOnce() -> Result<String>,
    verify: impl FnOnce(&str) -> Result<()>,
) -> Result<String> {
    let lock = open_regular(
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false),
        &path.with_extension("lock"),
    )?;
    lock.try_lock()
        .context("another process is staging this release")?;
    let result = (|| {
        let existing = path.try_exists()?.then(|| read_json(path)).transpose()?;
        let (record, recovering) = match existing {
            Some(StageRecord::Created(record)) => {
                ensure!(
                    recovery_id.is_none_or(|id| id == record.deploy_id),
                    "this release already records a different deployment ID"
                );
                require_allowed(Some(&record.deploy_id))?;
                (record, false)
            }
            Some(StageRecord::Pending(pending)) => {
                ensure!(
                    pending == attempt,
                    "pending stage is for a different descriptor or organization"
                );
                let deploy_id = recovery_id.filter(|id| !id.is_empty()).context(
                    "stage outcome is unknown. Recover it with stage --deployment-id <id>",
                )?;
                require_allowed(Some(deploy_id))?;
                (
                    Deployment {
                        deploy_id: deploy_id.into(),
                    },
                    true,
                )
            }
            None => {
                ensure!(recovery_id.is_none(), "no interrupted stage to recover");
                require_allowed(None)?;
                write_stage_record(path, &attempt)?;
                let deploy_id = create().context(
                    "could not confirm deployment creation. Recover it with stage --deployment-id <id>",
                )?;
                ensure!(
                    !deploy_id.is_empty(),
                    "Turnkey returned an empty deployment ID"
                );
                let record = Deployment { deploy_id };
                write_stage_record(path, &record)?;
                (record, false)
            }
        };
        verify(&record.deploy_id)?;
        if recovering {
            write_stage_record(path, &record)?;
        }
        Ok(record.deploy_id)
    })();
    lock.unlock().context("unlock stage record")?;
    result
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
        let output = capture_with_timeout(
            Command::new("docker").args([
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
            ]),
            IMAGE_INSPECTION_TIMEOUT,
        )?;
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
        let apps: Apps = tvc_json(&mut tvc(&["app", "list"]))?;
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
        let attempt = StageAttempt {
            organization_id: credentials.organization_id.clone(),
            descriptor_sha256: hex::encode(sha256(&serde_json::to_vec(&descriptor)?)),
        };
        let approved_input = copy_descriptor(&descriptor)?;
        let mut live = None;
        let deploy_id = stage_deployment(
            &self.path("deploy"),
            attempt,
            self.args.deployment_id.as_deref(),
            |candidate| {
                live = self.live_deployment()?;
                if self.network() == Network::Mainnet {
                    self.production_trust()?;
                    require_candidate(live.as_deref(), candidate)?;
                }
                Ok(())
            },
            || {
                #[derive(Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct CreatedDeployment {
                    deployment_id: String,
                }
                let mut command = tvc_create(
                    approved_input.path(),
                    std::env::vars_os().map(|(name, _)| name),
                );
                let created: CreatedDeployment = tvc_json(&mut command)?;
                Ok(created.deployment_id)
            },
            |id| {
                self.approved_deployment(id, &descriptor, &credentials)
                    .map(|_| ())
            },
        )?;
        println!("verified deployment {deploy_id}");
        if live.as_deref() != Some(&deploy_id) {
            println!("Review, approve, and provision it with tvc.");
        }
        Ok(())
    }

    pub(crate) fn staged_deployment(&self) -> Result<Deployment> {
        match read_json(&self.path("deploy"))? {
            StageRecord::Created(record) => Ok(record),
            StageRecord::Pending(_) => {
                anyhow::bail!("recover the interrupted stage before pinning")
            }
        }
    }
}

#[cfg(test)]
#[path = "../tests/stage.rs"]
mod tests;
