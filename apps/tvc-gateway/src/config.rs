//! Service configuration: the shared `config.yaml`, then one network's
//! overlay (`devnet.yaml` or `mainnet.yaml` beside it), then `TVC_GATEWAY_`
//! env overrides (nested fields split on `__`, e.g.
//! `TVC_GATEWAY_TURNKEY__BOOT_PROOF_API_KEY__PRIVATE_KEY`).

use std::net::SocketAddr;
use std::path::Path;

use figment::Figment;
use figment::providers::{Env, Format, Yaml};
use serde::Deserialize;
use spr_tvc_protocol::Network;

/// The shared settings every network overlay sits on, in the overlay's directory.
pub const BASE_FILE: &str = "config.yaml";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    Dev,
    Prod,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The network this gateway serves.
    pub network: Network,
    pub stage: Stage,
    pub listen: SocketAddr,
    pub metrics: MetricsConfig,
    /// `Authorization` value gatekeeper sends on every origin request. Secret.
    pub origin_auth_header: String,
    pub dev_api: DevApiConfig,
    /// The decryption-service enclave.
    pub enclave: EnclaveConfig,
    pub turnkey: TurnkeyConfig,
}

/// Helius dev-api (`ts-services/dev-api` in helius-labs/monorepo), which
/// resolves the API key a direct caller sends to its project.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevApiConfig {
    /// Without a trailing slash, such as `https://dev-api.helius.xyz/v0`.
    pub base_url: String,
    pub project_cache_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    pub statsd_endpoint: String,
    pub prefix: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnclaveConfig {
    /// Decryption-service TVC public ingress, without a trailing slash.
    pub base_url: String,
    pub request_timeout_ms: u64,
    pub max_body_bytes: usize,
    pub max_in_flight_per_project: u32,
    pub replay_window_secs: u64,
    pub replay_max_entries: usize,
    /// Redis every gateway task shares its replay guard through, such as
    /// `rediss://host:6379/2`. Absent, each process keeps its own.
    #[serde(default)]
    pub replay_redis_url: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnkeyConfig {
    pub api_base_url: String,
    /// Organization that owns the network's TVC application; Boot Proofs are
    /// read here.
    pub tvc_organization_id: String,
    pub boot_proof_api_key: TurnkeyApiKey,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnkeyApiKey {
    pub public_key: String,
    pub private_key: String,
}

pub const MIN_SECRET_LEN: usize = 32;

/// The shared config and the network overlay at `overlay`, such as
/// `configs/devnet.yaml`, under the environment.
pub fn load(overlay: &Path) -> anyhow::Result<Config> {
    let config: Config = files(overlay)?
        .merge(Env::prefixed("TVC_GATEWAY_").split("__"))
        .extract()?;
    config.validate()?;
    Ok(config)
}

/// `config.yaml` beside `overlay`, then `overlay`. Both must exist.
fn files(overlay: &Path) -> anyhow::Result<Figment> {
    anyhow::ensure!(
        overlay.file_name().is_some_and(|name| name != BASE_FILE),
        "--config names a network overlay, such as configs/devnet.yaml, not {}",
        overlay.display()
    );
    Ok(Figment::new()
        .merge(Yaml::file_exact(overlay.with_file_name(BASE_FILE)))
        .merge(Yaml::file_exact(overlay)))
}

impl Config {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.origin_auth_header.len() >= MIN_SECRET_LEN,
            "origin_auth_header must be at least {MIN_SECRET_LEN} bytes"
        );
        anyhow::ensure!(
            ["https://", "http://"]
                .iter()
                .any(|scheme| self.enclave.base_url.starts_with(scheme)),
            "enclave.base_url must be the {} enclave's URL, not {:?}",
            self.network,
            self.enclave.base_url
        );
        anyhow::ensure!(
            !self.enclave.base_url.ends_with('/'),
            "enclave.base_url must not end with '/'"
        );
        anyhow::ensure!(
            is_canonical_uuid(&self.turnkey.tvc_organization_id),
            "turnkey.tvc_organization_id must be the {} TVC application's organization, not {:?}",
            self.network,
            self.turnkey.tvc_organization_id
        );
        anyhow::ensure!(
            !self.dev_api.base_url.ends_with('/'),
            "dev_api.base_url must not end with '/'"
        );
        anyhow::ensure!(
            self.enclave.max_in_flight_per_project > 0,
            "enclave.max_in_flight_per_project must be positive"
        );
        anyhow::ensure!(
            self.enclave.replay_window_secs > 0 && self.enclave.replay_max_entries > 0,
            "enclave replay window and capacity must be positive"
        );
        Ok(())
    }
}

/// A lowercase hyphenated UUID, as Turnkey writes its IDs.
pub fn is_canonical_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => matches!(byte, b'0'..=b'9' | b'a'..=b'f'),
        })
}

#[cfg(test)]
#[path = "../tests/unit/network_configuration.rs"]
mod tests;
