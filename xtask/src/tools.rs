use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{ensure, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use toml_edit::DocumentMut;
use zeroize::Zeroizing;

use crate::read_json;

pub(crate) fn capture(command: &mut Command) -> Result<Vec<u8>> {
    let output = command
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("run {}", command.get_program().to_string_lossy()))?;
    if !output.status.success() {
        let details = if output.stderr.is_empty() {
            &output.stdout
        } else {
            &output.stderr
        };
        anyhow::bail!(
            "{} failed: {}",
            command.get_program().to_string_lossy(),
            String::from_utf8_lossy(details).trim()
        );
    }
    Ok(output.stdout)
}

pub(crate) fn run(command: &mut Command) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("run {:?}", command.get_program()))?;
    ensure!(
        status.success(),
        "{:?} failed ({status})",
        command.get_program()
    );
    Ok(())
}

pub(crate) fn tvc(args: &[&str]) -> Command {
    let mut command = Command::new("tvc");
    command.args(args);
    command
}

pub(crate) fn tvc_json<T: DeserializeOwned>(command: &mut Command) -> Result<T> {
    let json = capture(command.args(["--message-format", "json"]))?;
    let line = json
        .trim_ascii_end()
        .rsplit(|&b| b == b'\n')
        .next()
        .context("empty TVC response")?;
    serde_json::from_slice(line).context("decode TVC response")
}

const TVC_ORG: &str = "TVC_ORG_ID";
const TVC_PUBLIC: &str = "TVC_API_KEY_PUBLIC";
const TVC_PRIVATE: &str = "TVC_API_KEY_PRIVATE";
const TVC_API: &str = "https://api.turnkey.com";

#[derive(Deserialize)]
struct ApiKey {
    public_key: String,
    private_key: String,
}

pub(crate) struct Credentials {
    pub(crate) organization_id: String,
    api_base_url: String,
    public_key: String,
    private_key: Zeroizing<String>,
}

impl Credentials {
    pub(crate) fn load() -> Result<Self> {
        match [TVC_ORG, TVC_PUBLIC, TVC_PRIVATE]
            .map(|name| env::var(name).ok().filter(|value| !value.is_empty()))
        {
            [Some(organization_id), Some(public_key), Some(private_key)] => Ok(Self {
                organization_id,
                api_base_url: TVC_API.into(),
                public_key,
                private_key: Zeroizing::new(private_key),
            }),
            [None, None, None] => Self::profile(
                &env::home_dir()
                    .context("cannot find home directory")?
                    .join(".config/turnkey"),
            ),
            _ => anyhow::bail!("set all of {TVC_ORG}, {TVC_PUBLIC}, and {TVC_PRIVATE}, or none"),
        }
    }

    pub(crate) fn profile(config_dir: &Path) -> Result<Self> {
        let config = fs::read_to_string(config_dir.join("tvc.config.toml"))
            .context("read TVC login; run tvc login or set the TVC API key environment variables")?
            .parse::<DocumentMut>()
            .context("parse TVC login config")?;
        let name = config
            .get("active_org")
            .and_then(|item| item.as_str())
            .context("missing active_org")?;
        let profile = config
            .get("orgs")
            .and_then(|orgs| orgs.get(name))
            .context("missing active TVC profile")?;
        let field = |key| profile.get(key).and_then(|item| item.as_str());
        let organization_id = field("id")
            .context("missing TVC organization ID")?
            .to_owned();
        let path = PathBuf::from(field("api_key_path").context("missing TVC API key path")?);
        let ApiKey {
            public_key,
            private_key,
        } = read_json(&path)?;
        Ok(Self {
            organization_id,
            api_base_url: field("api_base_url").unwrap_or(TVC_API).to_owned(),
            public_key,
            private_key: Zeroizing::new(private_key),
        })
    }

    pub(crate) fn bridge(&self, args: &[&str]) -> Command {
        let mut command = bridge(args);
        command.envs([
            (TVC_ORG, self.organization_id.as_str()),
            (TVC_PUBLIC, self.public_key.as_str()),
            (TVC_PRIVATE, self.private_key.as_str()),
            ("SPR_TVC_API_BASE_URL", &self.api_base_url),
        ]);
        command
    }
}

pub(crate) fn bridge(args: &[&str]) -> Command {
    let mut command = Command::new("node");
    command.arg("xtask/release-api.ts").args(args);
    command
}

pub(crate) fn verify_live(credentials: &Credentials, input: &impl Serialize) -> Result<()> {
    let mut child = credentials
        .bridge(&["verify"])
        .stdin(Stdio::piped())
        .spawn()
        .context("start live verifier; run just setup build-ts")?;
    let write = serde_json::to_writer(
        child.stdin.take().context("missing live verifier input")?,
        input,
    );
    let status = child.wait()?;
    ensure!(status.success(), "live attestation did not verify");
    write?;
    Ok(())
}
