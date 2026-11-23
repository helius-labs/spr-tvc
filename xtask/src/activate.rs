use std::io::{self, IsTerminal};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
use serde::Deserialize;

use crate::stage::Deployment;
use crate::tools::{capture_check, check_output, decode_tvc, tvc, tvc_json, Credentials};
use crate::{write_json, Release};

const BOOT_TIMEOUT: Duration = Duration::from_secs(300);
const BOOT_POLL: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OperatorSets {
    manifest_set: OperatorSet,
    share_set: OperatorSet,
    manifest_approvals: Vec<Approval>,
}

#[derive(Deserialize)]
struct OperatorSet {
    threshold: u8,
    operators: Vec<Operator>,
}

#[derive(Deserialize)]
struct Operator {
    id: String,
}

#[derive(Deserialize)]
struct Approval {
    operator: Operator,
}

#[derive(Deserialize)]
#[serde(
    tag = "reason",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum RuntimeStatus {
    DeploymentRuntimeStatus {
        deployment_id: String,
        app_id: String,
        is_targeted: bool,
        replicas: Replicas,
    },
    CommandError {
        code: String,
        message: String,
    },
}

#[derive(Deserialize)]
struct Replicas {
    ready: u32,
    desired: u32,
}

impl RuntimeStatus {
    fn ready(&self, success: bool, record: &Deployment, app: &str) -> Result<bool> {
        match self {
            Self::DeploymentRuntimeStatus {
                deployment_id,
                app_id,
                is_targeted,
                replicas,
            } if success => {
                ensure!(
                    deployment_id == &record.deploy_id && app_id == app,
                    "runtime status belongs to a different deployment"
                );
                if !is_targeted || replicas.desired == 0 {
                    return Ok(false);
                }
                ensure!(
                    record.replicas.is_none_or(
                        |replicas_requested| replicas_requested.get() == replicas.desired
                    ),
                    "Turnkey reports {} desired replicas for deployment {}",
                    replicas.desired,
                    record.deploy_id
                );
                Ok(replicas.ready == replicas.desired)
            }
            Self::CommandError { code, .. } if !success && code == "not_found" => Ok(false),
            Self::CommandError { message, .. } => {
                anyhow::bail!("Turnkey runtime status failed: {message}")
            }
            _ => anyhow::bail!("Turnkey did not return a successful runtime status"),
        }
    }
}

impl OperatorSets {
    fn operators(&self) -> Result<[&str; 2]> {
        let [first, second] = self.manifest_set.operators.as_slice() else {
            anyhow::bail!("--activate requires two hosted operators in each set");
        };
        let ids = [first.id.as_str(), second.id.as_str()];
        ensure!(
            !ids.contains(&"")
                && first.id != second.id
                && self.manifest_set.threshold == 2
                && self.share_set.threshold == 2
                && self.share_set.operators.len() == 2
                && ids
                    .iter()
                    .all(|id| self.share_set.operators.iter().any(|op| op.id == *id)),
            "--activate requires the same two operators in both 2-of-2 sets"
        );
        Ok(ids)
    }
}

fn activation_command(action: &str, deploy_id: &str) -> Command {
    let mut command = tvc(&["deploy", action, "--deploy-id", deploy_id]);
    for key in [
        "TVC_DANGEROUS_SKIP_INTERACTIVE",
        "TVC_DANGEROUS_SKIP_VERIFICATION",
        "TVC_DRY_RUN",
        "TVC_SKIP_POST",
        "TVC_NON_INTERACTIVE",
        "TVC_MANIFEST",
        "TVC_MANIFEST_ID",
        "TVC_OPERATOR_SEED",
        "TVC_OPERATOR_SEED_PATH",
        "TVC_APPROVAL_OUT",
        "TVC_PROVISION_BUNDLE_OUT",
    ] {
        command.env_remove(key);
    }
    command
}

fn wait_for_provisioning(deploy_id: &str) -> Result<()> {
    let deadline = Instant::now() + BOOT_TIMEOUT;
    loop {
        let mut command = activation_command("provisioning-details", deploy_id);
        match capture_check(command.args(["--message-format", "json"])) {
            Ok(_) => return Ok(()),
            Err(error)
                if error.to_string().contains("attestation document missing")
                    && Instant::now() < deadline =>
            {
                thread::sleep(BOOT_POLL);
            }
            Err(error) => {
                return Err(error).context("wait for verified Turnkey provisioning details")
            }
        }
    }
}

impl Release<'_> {
    fn runtime_ready(&self, record: &Deployment) -> Result<bool> {
        let (status, output) = check_output(
            activation_command("get-status", &record.deploy_id).args(["--message-format", "json"]),
        )?;
        let runtime: RuntimeStatus = decode_tvc(&output)?;
        runtime.ready(status.success(), record, &self.app.app_id)
    }

    pub(crate) fn activate(
        &self,
        record: &mut Deployment,
        credentials: &Credentials,
    ) -> Result<()> {
        if let Some(live) = self.live_deployment()? {
            ensure!(
                live == record.deploy_id,
                "Turnkey selected a different deployment ({live})"
            );
        }
        if self.runtime_ready(record)? {
            return Ok(());
        }
        let sets: OperatorSets = serde_json::from_slice(&capture_check(
            &mut credentials.bridge(&["deployment", &record.deploy_id]),
        )?)?;
        let operators = sets.operators()?;
        for operator in operators {
            if sets
                .manifest_approvals
                .iter()
                .any(|approval| approval.operator.id == operator)
            {
                continue;
            }
            ensure!(
                io::stdin().is_terminal(),
                "rerun --activate in a terminal to review the manifest"
            );
            let status = activation_command("approve", &record.deploy_id)
                .args(["--operator-id", operator])
                .status()
                .context("start Turnkey manifest review")?;
            ensure!(
                status.success(),
                "manifest review did not complete for operator {operator}"
            );
        }

        let pending_shares: Vec<_> = operators
            .into_iter()
            .filter(|id| {
                !record
                    .hosted_share_receipts
                    .iter()
                    .any(|receipt| receipt == id)
            })
            .collect();
        if !pending_shares.is_empty() {
            wait_for_provisioning(&record.deploy_id)?;
        }
        for operator in pending_shares {
            #[derive(Deserialize)]
            struct Receipt {
                reason: String,
            }
            let receipt: Receipt = tvc_json(
                activation_command("provision", &record.deploy_id)
                    .args(["--operator-id", operator]),
                capture_check,
            )?;
            ensure!(
                receipt.reason == "provisioning_share_created",
                "unexpected share receipt for operator {operator}"
            );
            record.hosted_share_receipts.push(operator.to_owned());
            write_json(&self.path("deploy"), record)?;
        }

        let deadline = Instant::now() + BOOT_TIMEOUT;
        println!("Waiting for Turnkey replicas to become ready");
        loop {
            if self.runtime_ready(record)? {
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "deployment {} did not become live",
                record.deploy_id
            );
            thread::sleep(BOOT_POLL);
        }
    }
}

#[cfg(test)]
#[path = "../tests/activate.rs"]
mod tests;
