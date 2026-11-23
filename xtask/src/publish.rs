use std::num::NonZeroU64;
use std::process::Command;

use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use spr_tvc_protocol::types::Network;

use crate::tools::capture_check;

pub(crate) const REPO: &str = "helius-labs/spr-tvc";
pub(crate) const WORKFLOW: &str = ".github/workflows/publish-enclave-image.yml";
const API_VERSION: &str = "X-GitHub-Api-Version: 2026-03-10";

pub(crate) fn publish(network: Network) -> Result<NonZeroU64> {
    #[derive(Deserialize)]
    struct Dispatch {
        workflow_run_id: NonZeroU64,
    }
    let response = capture_check(Command::new("gh").args([
        "api",
        "--method",
        "POST",
        &format!("repos/{REPO}/actions/workflows/publish-enclave-image.yml/dispatches"),
        "-H",
        API_VERSION,
        "-f",
        "ref=main",
        "-f",
        &format!("inputs[network]={network}"),
    ]))?;
    let id = serde_json::from_slice::<Dispatch>(&response)
        .context("decode GitHub's publish run ID")?
        .workflow_run_id;
    eprintln!("Approve image-publish at https://github.com/{REPO}/actions/runs/{id}");
    let status = Command::new("gh")
        .args([
            "run",
            "watch",
            &id.to_string(),
            "--repo",
            REPO,
            "--exit-status",
            "--compact",
            "--interval",
            "10",
        ])
        .status()
        .context("watch the GitHub publish run")?;
    ensure!(
        status.success(),
        "publish run {id} did not complete successfully"
    );
    Ok(id)
}

pub(crate) fn image_from_run(id: NonZeroU64) -> Result<(String, String)> {
    #[derive(Deserialize)]
    struct Run {
        path: String,
        conclusion: Option<String>,
        head_sha: String,
        run_attempt: NonZeroU64,
    }
    let response = capture_check(
        Command::new("gh").args(["api", &format!("repos/{REPO}/actions/runs/{id}")]),
    )?;
    let run: Run = serde_json::from_slice(&response).context("decode GitHub publish run")?;
    ensure!(
        run.path == WORKFLOW && run.conclusion.as_deref() == Some("success"),
        "run {id} must be a successful enclave image publish"
    );
    let log = capture_check(Command::new("gh").args([
        "run",
        "view",
        &id.to_string(),
        "--repo",
        REPO,
        "--attempt",
        &run.run_attempt.to_string(),
        "--log",
    ]))?;
    Ok((
        reported_image(std::str::from_utf8(&log)?)?.to_owned(),
        run.head_sha,
    ))
}

fn reported_image(log: &str) -> Result<&str> {
    let mut images = log.lines().filter_map(|line| {
        let message = line.strip_prefix("publish\tReport pinned reference\t")?;
        let (_, body) = message.split_once(' ')?;
        body.trim().strip_prefix("IMAGE: ")
    });
    let image = images
        .next()
        .context("publish run did not report a pinned image")?;
    ensure!(
        images.next().is_none(),
        "publish run reported multiple images"
    );
    Ok(image)
}

#[cfg(test)]
#[path = "../tests/publish.rs"]
mod tests;
