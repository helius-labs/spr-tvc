mod policy;
mod stage;
mod tools;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use spr_tvc_wire::encoding::{decimal_u64, hex as wire_hex};
use spr_tvc_wire::types::Network;

const APP: &str = "decryption-service";
const DEPLOY_DIR: &str = "decryption-service/deploy";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Deploy,
    Pin,
}

#[derive(Parser)]
#[command(
    bin_name = "cargo xtask",
    about = "Deploy a Turnkey enclave and pin the live release"
)]
struct Cli {
    #[command(subcommand)]
    action: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create or resume a deployment. Operators approve and provision it.
    Deploy(ReleaseCommand),
    /// Check a live deployment and write the devnet pin or the mainnet policy request.
    Pin(ReleaseCommand),
}

#[derive(Parser)]
struct ReleaseCommand {
    #[arg(long, value_parser = parse_network)]
    network: Network,
    /// Published image, `repository:decryption-service-<network>-<commit>@sha256:<digest>`.
    #[arg(long)]
    image: Option<String>,
    #[arg(long)]
    source_commit: Option<String>,
    /// Resume this deployment, or pin this id. A signed mainnet check uses the live id.
    #[arg(long)]
    deploy_id: Option<String>,
    #[arg(long)]
    signed_policy: Option<PathBuf>,
    /// Mainnet policy request. Defaults to `policy-request.json`.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Manifests below this nonce are rejected. The floor starts at zero.
    #[arg(long, default_value_t = 0)]
    minimum_manifest_nonce: u64,
}

pub(crate) struct Inputs {
    pub(crate) network: Network,
    pub(crate) image: String,
    pub(crate) source_commit: Option<String>,
    pub(crate) deploy_id: Option<String>,
    pub(crate) signed_policy: Option<PathBuf>,
    pub(crate) out: Option<PathBuf>,
    pub(crate) release_id: String,
    pub(crate) minimum_manifest_nonce: u64,
}

fn parse_network(value: &str) -> Result<Network, &'static str> {
    match value {
        "devnet" => Ok(Network::Devnet),
        "mainnet" => Ok(Network::Mainnet),
        _ => Err("use devnet or mainnet"),
    }
}

impl ReleaseCommand {
    fn validate(&self, action: Action) -> Result<()> {
        let pinning = action == Action::Pin;
        let signed = self.signed_policy.is_some();
        ensure!(
            !signed || (pinning && self.network == Network::Mainnet),
            "--signed-policy is the signed mainnet pin"
        );
        ensure!(
            self.out.is_none() || (pinning && self.network == Network::Mainnet && !signed),
            "--out is the mainnet policy request"
        );
        if action == Action::Deploy {
            ensure!(self.image.is_some(), "deploy requires --image");
        }
        if self.network == Network::Mainnet {
            let inferred = pinning && signed && self.source_commit.is_none();
            ensure!(
                inferred
                    || self
                        .source_commit
                        .as_deref()
                        .is_some_and(|sha| lower_hex(sha, 40)),
                "mainnet requires --source-commit with the reviewed full commit hash"
            );
        } else {
            ensure!(
                self.source_commit.is_none(),
                "--source-commit is a mainnet input"
            );
            ensure!(
                self.deploy_id.is_some() || action == Action::Deploy,
                "pin requires --deploy-id"
            );
        }
        if pinning && !(self.network == Network::Mainnet && signed) {
            ensure!(self.deploy_id.is_some(), "pin requires --deploy-id");
            ensure!(self.image.is_some(), "pin requires --image");
        }
        if let Some(id) = &self.deploy_id {
            ensure!(!id.is_empty(), "deploy id is empty");
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
    args: &'a Inputs,
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

    fn pin_path(&self) -> PathBuf {
        Path::new("client/sdk/releases").join(format!("{}.json", self.network()))
    }

    fn request_path(&self) -> PathBuf {
        self.args
            .out
            .clone()
            .unwrap_or_else(|| PathBuf::from("policy-request.json"))
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
    use std::io::Write;
    let parent = path.parent();
    let dir = match parent {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    fs::create_dir_all(dir)?;
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    writeln!(file)?;
    file.persist(path)
        .with_context(|| format!("write {}", path.display()))?;
    println!("wrote {}", path.display());
    Ok(())
}

fn network_config(config: &ReleaseConfig, network: Network) -> Result<&NetworkConfig> {
    match network {
        Network::Devnet => Ok(&config.networks.devnet),
        Network::Mainnet => config
            .networks
            .mainnet
            .as_ref()
            .context("no mainnet app in release.json"),
    }
}

fn run(action: Action, command: ReleaseCommand) -> Result<()> {
    command.validate(action)?;
    let config: ReleaseConfig = read_json(Path::new(DEPLOY_DIR).join("release.json").as_path())?;
    let app = network_config(&config, command.network)?;
    ensure!(
        !app.app_id.is_empty()
            && !app.endpoint.is_empty()
            && !app.quorum_key_id.is_empty()
            && app.quorum_key_epoch > 0,
        "incomplete {} app config",
        command.network
    );
    let mut image = command.image.clone();
    let mut source_commit = command.source_commit.clone();
    let mut deploy_id = command.deploy_id.clone();
    if image.is_none() || (action == Action::Pin && deploy_id.is_none()) {
        let live = stage::live_deployment_id(&app.app_id)?.context("the deployment is not live")?;
        let id = deploy_id.clone().unwrap_or_else(|| live.clone());
        ensure!(id == live, "the deployment is not live");
        if image.is_none() {
            let url = policy::deployment_container_url(&id)?;
            let resolved = stage::image_reference(&url, &config.image_repository, command.network)?;
            if source_commit.is_none() {
                source_commit = resolved.source_commit;
            }
            image = Some(resolved.image);
        }
        deploy_id = Some(id);
    }
    let image = image.context("pin requires --image")?;
    if command.network == Network::Mainnet && source_commit.is_none() {
        let digest = stage::image_digest(&image, &config.image_repository, command.network, None)?;
        source_commit = Some(stage::attested_source_commit(
            &config.image_repository,
            digest,
        )?);
    }
    let release_id =
        stage::release_label(&image, &config.image_repository, command.network)?.to_owned();
    if let Some(commit) = &source_commit {
        stage::image_digest(
            &image,
            &config.image_repository,
            command.network,
            Some(commit),
        )?;
    }
    let inputs = Inputs {
        network: command.network,
        image,
        source_commit,
        deploy_id,
        signed_policy: command.signed_policy,
        out: command.out,
        release_id,
        minimum_manifest_nonce: command.minimum_manifest_nonce,
    };
    let release = Release {
        args: &inputs,
        config: &config,
        app,
    };
    match action {
        Action::Deploy => release.deploy(),
        Action::Pin => release.pin(),
    }
}

fn main() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("missing workspace root")?;
    let Cli { action } = Cli::parse();
    let (kind, mut command) = match action {
        Command::Deploy(command) => (Action::Deploy, command),
        Command::Pin(command) => (Action::Pin, command),
    };
    command.signed_policy = command.signed_policy.map(std::path::absolute).transpose()?;
    command.out = command.out.map(std::path::absolute).transpose()?;
    std::env::set_current_dir(root)?;
    run(kind, command)
}

#[cfg(test)]
#[path = "../tests/harness.rs"]
mod tests;
