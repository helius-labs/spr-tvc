mod nitro;
mod policy;
mod stage;
mod tools;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use clap::{Parser, ValueEnum};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use spr_tvc_protocol::encoding::{decimal_u64, hex as wire_hex};
use spr_tvc_protocol::types::Network;

const APP: &str = "decryption-service";
const DEPLOY_DIR: &str = "enclave/deploy";

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Phase {
    Describe,
    Stage,
    Prepare,
    Pin,
}

#[derive(Parser)]
#[command(
    bin_name = "cargo xtask",
    about = "Describe, stage, and pin an enclave release"
)]
struct Args {
    phase: Phase,
    #[arg(value_parser = release_id)]
    release_id: String,
    #[arg(long, value_parser = parse_network)]
    network: Network,
    #[arg(long)]
    image: Option<String>,
    #[arg(long)]
    source_commit: Option<String>,
    #[arg(long)]
    signed_policy: Option<PathBuf>,
    /// Recover an interrupted stage using its authenticated Turnkey deployment ID.
    #[arg(long)]
    deployment_id: Option<String>,
}

fn parse_network(value: &str) -> Result<Network, &'static str> {
    match value {
        "devnet" => Ok(Network::Devnet),
        "mainnet" => Ok(Network::Mainnet),
        _ => Err("use devnet or mainnet"),
    }
}

fn release_id(value: &str) -> Result<String, &'static str> {
    let valid_char = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    if (2..=64).contains(&value.len())
        && valid_char(value.as_bytes()[0])
        && value.bytes().all(|byte| valid_char(byte) || byte == b'-')
    {
        Ok(value.to_owned())
    } else {
        Err("use 2 to 64 lowercase letters, digits, or hyphens and start with a letter or digit")
    }
}

impl Args {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.deployment_id.is_none() || self.phase == Phase::Stage,
            "--deployment-id is only used to recover an interrupted stage"
        );
        ensure!(
            self.image.is_some() == (self.phase == Phase::Describe),
            "--image is required for describe and only used by that phase"
        );
        ensure!(
            self.signed_policy.is_some()
                == (self.network == Network::Mainnet && self.phase == Phase::Pin),
            "--signed-policy is required for mainnet pin and only used by that phase"
        );
        if self.network == Network::Mainnet {
            ensure!(
                self.source_commit
                    .as_deref()
                    .is_some_and(|sha| lower_hex(sha, 40)),
                "mainnet requires --source-commit with the reviewed full commit hash"
            );
        } else {
            ensure!(self.phase != Phase::Prepare, "prepare is a mainnet phase");
            ensure!(
                self.source_commit.is_none(),
                "--source-commit is a mainnet input"
            );
        }
        Ok(())
    }
}

type Pcrs = std::collections::BTreeMap<u8, String>;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseConfig {
    image_repository: String,
    qos_version: String,
    turnkey_trust_root_id: String,
    qos_identity_pcrs: Pcrs,
    policy_validity_days: u64,
    networks: Networks,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Networks {
    devnet: NetworkConfig,
    mainnet: Option<NetworkConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NetworkConfig {
    app_id: String,
    endpoint: String,
    qos_version: Option<String>,
    #[serde(with = "wire_hex")]
    security_domain_id: [u8; 32],
    quorum_key_id: String,
    #[serde(with = "decimal_u64")]
    quorum_key_epoch: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppConfig {
    #[serde(with = "wire_hex")]
    quorum_public_key: Vec<u8>,
}

struct Release<'a> {
    args: &'a Args,
    config: &'a ReleaseConfig,
    app: &'a NetworkConfig,
}

impl Release<'_> {
    fn network(&self) -> Network {
        self.args.network
    }

    fn qos_version(&self) -> &str {
        self.app
            .qos_version
            .as_deref()
            .unwrap_or(&self.config.qos_version)
    }

    fn path(&self, suffix: &str) -> PathBuf {
        Path::new(DEPLOY_DIR)
            .join(self.network().as_str())
            .join(format!("{}.{suffix}.json", self.args.release_id))
    }

    fn pin_path(&self) -> PathBuf {
        Path::new("sdk/releases").join(format!("{}.json", self.network()))
    }
}

fn app_config(network: Network) -> Result<AppConfig> {
    read_json(
        &Path::new(DEPLOY_DIR)
            .join(network.as_str())
            .join(format!("spr-{APP}-{network}.app.json")),
    )
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&data).with_context(|| format!("decode {}", path.display()))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    store_json(path, value)?;
    println!("wrote {}", path.display());
    Ok(())
}

fn store_json(path: &Path, value: &impl Serialize) -> Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .context("JSON output needs a parent directory")?;
    fs::create_dir_all(dir)?;
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    writeln!(file)?;
    file.persist(path)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn run(args: &Args) -> Result<()> {
    args.validate()?;
    let config: ReleaseConfig = read_json(Path::new(DEPLOY_DIR).join("release.json").as_path())?;
    let app = match args.network {
        Network::Devnet => &config.networks.devnet,
        Network::Mainnet => config
            .networks
            .mainnet
            .as_ref()
            .context("no mainnet app in release.json")?,
    };
    ensure!(
        !app.app_id.is_empty()
            && !app.endpoint.is_empty()
            && !app.quorum_key_id.is_empty()
            && app.quorum_key_epoch > 0,
        "incomplete {} app config",
        args.network
    );
    let release = Release {
        args,
        config: &config,
        app,
    };
    match args.phase {
        Phase::Describe => release.describe(),
        Phase::Stage => release.stage(),
        Phase::Prepare | Phase::Pin => release.policy(),
    }
}

fn main() -> Result<()> {
    let mut command = std::env::args_os();
    if command.nth(1).is_some_and(|phase| phase == "nitro-sign") {
        let args = nitro::Args::parse_from(std::iter::once("nitro-sign".into()).chain(command));
        return nitro::sign(args);
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("missing workspace root")?;
    let mut args = Args::parse();
    args.signed_policy = args.signed_policy.map(std::path::absolute).transpose()?;
    std::env::set_current_dir(root)?;
    run(&args)
}

#[cfg(test)]
#[path = "../tests/release.rs"]
mod tests;
