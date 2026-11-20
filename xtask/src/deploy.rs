use std::process::Command;

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use spr_tvc_protocol::types::{Network, ServiceInfo};

use crate::tools::{bridge, capture, run, tvc, tvc_json, tvc_quiet, wait_for};
use crate::{lower_hex, read_json, write_json, Release, APP};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Descriptor {
    pub(crate) pivot_container_image_url: String,
    pub(crate) expected_pivot_digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Deployment {
    pub(crate) deploy_id: String,
    approved: Vec<String>,
    provisioned: Vec<String>,
    pub(crate) live: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeploymentId {
    deployment_id: String,
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
        lower_hex(digest, 64) && !suffix.is_empty() && !suffix.contains('@'),
        "image needs a network tag and a lowercase SHA-256 digest"
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
    pub(crate) fn verify_image(&self, image: &str) -> Result<()> {
        let mainnet = self.network() == Network::Mainnet;
        let commit = if mainnet {
            Some(
                self.args
                    .source_commit
                    .as_deref()
                    .context("missing reviewed source commit")?,
            )
        } else {
            None
        };
        let repository = &self.config.image_repository;
        let digest = image_digest(image, repository, self.network(), commit)?;
        if let Some(commit) = commit {
            run(&mut provenance_command(repository, digest, commit))?;
        }
        Ok(())
    }

    pub(crate) fn build(&self) -> Result<()> {
        let image = self
            .args
            .image
            .as_deref()
            .context("build needs --image from publish-enclave-image")?;
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
            "/tvc_app",
        ]))?;
        let digest = std::str::from_utf8(&output)?
            .split_ascii_whitespace()
            .next()
            .filter(|digest| lower_hex(digest, 64))
            .context("could not read /tvc_app SHA-256")?;
        write_json(
            &self.path("deployment"),
            &json!({
                "appId": self.app.app_id,
                "qosVersion": self.qos_version(),
                "pivotContainerImageUrl": image,
                "pivotPath": "/tvc_app",
                "pivotArgs": [
                    "--host", "0.0.0.0", "--port", "3000",
                    "--security-domain-id", &hex::encode(self.app.security_domain_id),
                    "--release-id", &self.args.release_id,
                    "--quorum-key-id", &self.app.quorum_key_id,
                    "--quorum-key-epoch", &self.app.quorum_key_epoch.to_string(),
                ],
                "expectedPivotDigest": digest,
                "dangerousDeployDebugMode": false,
                "healthCheckType": "TVC_HEALTH_CHECK_TYPE_HTTP",
                "healthCheckPort": 3000,
                "publicIngressPort": 3000,
            }),
        )
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

    pub(crate) fn await_info(&self, descriptor: &Descriptor) -> Result<ServiceInfo> {
        wait_for(
            &format!("{} to serve {}", self.app.endpoint, self.args.release_id),
            || {
                let info: ServiceInfo =
                    serde_json::from_slice(&capture(&mut bridge(&["info", &self.app.endpoint]))?)?;
                ensure!(
                    info.release_id == self.args.release_id
                        && hex::encode(info.executable_digest) == descriptor.expected_pivot_digest,
                    "live discovery does not match the release and executable"
                );
                Ok(info)
            },
        )
    }

    pub(crate) fn deploy(&self) -> Result<()> {
        let descriptor_path = self.path("deployment");
        let descriptor: Descriptor = read_json(&descriptor_path).context("run build first")?;
        let path = self.path("deploy");
        let existing: Option<Deployment> = if path.try_exists()? {
            Some(read_json(&path)?)
        } else {
            None
        };
        if self.network() == Network::Mainnet {
            self.production_trust()?;
            self.verify_image(&descriptor.pivot_container_image_url)?;
            require_candidate(
                self.live_deployment()?.as_deref(),
                existing.as_ref().map(|record| record.deploy_id.as_str()),
            )?;
        }
        let mut record = match existing {
            Some(record) => record,
            None => {
                let id: DeploymentId =
                    tvc_json(tvc(&["deploy", "create", "--config-file"]).arg(&descriptor_path))?;
                let record = Deployment {
                    deploy_id: id.deployment_id,
                    approved: vec![],
                    provisioned: vec![],
                    live: false,
                };
                write_json(&path, &record)?;
                record
            }
        };
        if self.network() == Network::Mainnet {
            self.approved_deployment(
                &record.deploy_id,
                &descriptor,
                &crate::tools::Credentials::load()?,
            )?;
            println!(
                "staged {}. Operators approve and provision this candidate independently",
                record.deploy_id
            );
            return Ok(());
        }
        if self.args.prune_deployments {
            self.prune(&record.deploy_id)?;
        }
        self.provision_devnet(&path, &mut record)?;
        self.await_info(&descriptor)?;
        Ok(())
    }

    fn provision_devnet(&self, path: &std::path::Path, record: &mut Deployment) -> Result<()> {
        let mut operators = Vec::new();
        for (index, id) in self.app.operator_ids.iter().enumerate() {
            let seed = self
                .args
                .operator_seeds
                .as_ref()
                .map(|dir| dir.join(format!("operator-{}.seed", index + 1)));
            if seed.as_ref().is_none_or(|path| path.is_file()) {
                operators.push((id, seed));
            }
        }
        ensure!(!operators.is_empty(), "no operator-<n>.seed files found");
        let deploy_id = record.deploy_id.clone();
        for (id, seed) in &operators {
            if record.approved.contains(id) {
                continue;
            }
            let mut approve = tvc(&["deploy", "approve", "--deploy-id", &deploy_id]);
            if let Some(seed) = seed {
                approve.arg("--operator-seed-path").arg(seed);
            } else {
                approve.args(["--operator-id", id]);
            }
            operator_command(&mut approve, self.args.unattended)?;
            record.approved.push((*id).clone());
            write_json(path, record)?;
        }

        if operators
            .iter()
            .any(|(id, _)| !record.provisioned.contains(id))
        {
            wait_for("the provisioning attestation", || {
                tvc_quiet(&mut tvc(&[
                    "deploy",
                    "provisioning-details",
                    "--deploy-id",
                    &deploy_id,
                ]))
            })?;
        }
        for (id, seed) in operators {
            if record.provisioned.contains(id) {
                continue;
            }
            if let Some(seed) = seed {
                let metadata = self
                    .args
                    .quorum_key_metadata
                    .as_deref()
                    .context("missing Quorum key metadata")?;
                let scratch = tempfile::tempdir()?;
                let bundle = scratch.path().join("bundle.json");
                let share = scratch.path().join("share.json");
                tvc_quiet(
                    tvc(&[
                        "deploy",
                        "provisioning-details",
                        "--deploy-id",
                        &deploy_id,
                        "--provision-bundle-out",
                    ])
                    .arg(&bundle),
                )?;
                operator_command(
                    tvc(&["keys", "re-encrypt-local-share", "--quorum-key-metadata"])
                        .arg(metadata)
                        .arg("--provision-bundle")
                        .arg(bundle)
                        .arg("--operator-seed-path")
                        .arg(seed)
                        .arg("--re-encrypted-out")
                        .arg(&share),
                    self.args.unattended,
                )?;
                tvc_quiet(
                    tvc(&["deploy", "post-share", "--re-encrypted-share"])
                        .arg(share)
                        .args(["--share-operator-id", id]),
                )?;
            } else {
                tvc_quiet(&mut tvc(&[
                    "deploy",
                    "provision",
                    "--deploy-id",
                    &deploy_id,
                    "--operator-id",
                    id,
                ]))?;
            }
            record.provisioned.push(id.clone());
            write_json(path, record)?;
        }
        if !record.live {
            #[derive(Deserialize)]
            struct Status {
                replicas: Replicas,
            }
            #[derive(Deserialize)]
            struct Replicas {
                ready: u32,
            }
            wait_for("a ready replica", || {
                let status: Status = tvc_json(&mut tvc(&[
                    "deploy",
                    "get-status",
                    "--deploy-id",
                    &deploy_id,
                ]))?;
                ensure!(status.replicas.ready > 0, "no ready replica");
                Ok(())
            })?;
            if self.live_deployment()?.as_deref() != Some(&deploy_id) {
                tvc_quiet(&mut tvc(&[
                    "app",
                    "set-live-deploy",
                    "--deploy-id",
                    &deploy_id,
                ]))?;
            }
            record.live = true;
            write_json(path, record)?;
        }
        Ok(())
    }

    fn prune(&self, candidate: &str) -> Result<()> {
        use serde_json::Value;
        #[derive(Deserialize)]
        struct AppStatus {
            deployments: Vec<DeploymentId>,
        }
        let live = self.live_deployment()?;
        let status: AppStatus =
            tvc_json(&mut tvc(&["app", "status", "--app-id", &self.app.app_id]))?;
        let mut older = Vec::new();
        for deployment in status.deployments {
            let id = deployment.deployment_id;
            if id != candidate && Some(id.as_str()) != live.as_deref() {
                let info: Value = tvc_json(&mut tvc(&["deploy", "status", "--deploy-id", &id]))?;
                let seconds = &info["createdAt"]["seconds"];
                let timestamp = seconds
                    .as_i64()
                    .or_else(|| seconds.as_str()?.parse().ok())
                    .context("missing deployment creation time")?;
                older.push((timestamp, id));
            }
        }
        let keep = 1 + usize::from(live.as_deref().is_some_and(|id| id != candidate));
        older.sort_unstable();
        let count = (older.len() + keep).saturating_sub(3);
        for (_, id) in older.into_iter().take(count) {
            ensure!(
                self.live_deployment()?.as_deref() != Some(&id),
                "deployment {id} is live"
            );
            println!("deleting inactive deployment {id}");
            tvc_quiet(&mut tvc(&["deploy", "delete", "--deploy-id", &id]))?;
        }
        Ok(())
    }
}

fn operator_command(command: &mut Command, unattended: bool) -> Result<()> {
    if unattended {
        tvc_quiet(command.arg("--dangerous-skip-interactive"))
    } else {
        run(command)
    }
}

#[cfg(test)]
#[path = "../tests/deploy.rs"]
mod tests;
