//! The measured configuration is parsed and checked before any enclave I/O.

use std::{
    fs::File,
    io::{self, Read},
    num::NonZeroU64,
    path::PathBuf,
};

use clap::Parser;
use serde::{de::Error as _, Deserialize, Deserializer};
use spr_tvc_protocol::encoding::{decimal_u64, hex, parse_strict_json};

use crate::{
    custody::{Custody, Recipients},
    custody_relay::RelayAuthorities,
};

#[derive(Parser)]
#[command(version = openssl::version::version())]
pub struct Config {
    #[arg(default_value = "/configuration.json")]
    pub(super) configuration: PathBuf,
    /// Validate the measured input without opening a Nitro device or listener.
    #[arg(long)]
    pub(super) check_configuration: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Configuration {
    #[serde(with = "hex")]
    pub(super) security_domain_id: [u8; 32],
    pub(super) release_id: String,
    pub(super) deployment: Deployment,
}

#[derive(Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "lowercase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(super) enum Deployment {
    Serve {
        #[serde(deserialize_with = "deserialize_custody")]
        custody: Custody,
    },
    Relay {
        #[serde(deserialize_with = "deserialize_relay_epoch")]
        custody_epoch: NonZeroU64,
        #[serde(deserialize_with = "deserialize_relay_authorities")]
        approval_keys: RelayAuthorities,
    },
    Initialize {
        #[serde(deserialize_with = "deserialize_recipients")]
        recipient_public_keys: Recipients,
    },
    Rotate {
        #[serde(deserialize_with = "deserialize_custody")]
        previous: Custody,
        #[serde(deserialize_with = "deserialize_recipients")]
        recipient_public_keys: Recipients,
    },
}

fn deserialize_custody<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Custody, D::Error> {
    let custody = Custody::deserialize(deserializer)?;
    custody.validate().map_err(D::Error::custom)?;
    Ok(custody)
}

fn deserialize_relay_epoch<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<NonZeroU64, D::Error> {
    NonZeroU64::new(decimal_u64::deserialize(deserializer)?)
        .ok_or_else(|| D::Error::custom("invalid relay epoch"))
}

fn deserialize_relay_authorities<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<RelayAuthorities, D::Error> {
    let keys: Vec<[u8; 65]> = hex::deserialize(deserializer)?;
    RelayAuthorities::parse(
        keys.try_into()
            .map_err(|_| D::Error::custom("expected three recovery relay authorities"))?,
    )
    .map_err(D::Error::custom)
}

fn deserialize_recipients<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Recipients, D::Error> {
    let keys: Vec<Vec<u8>> = hex::deserialize(deserializer)?;
    Recipients::parse(&keys).map_err(D::Error::custom)
}

pub(super) fn read_configuration(path: PathBuf) -> io::Result<Configuration> {
    const MAX_CONFIG: u64 = 24 * 1024;
    let mut json = String::new();
    File::open(path)?
        .take(MAX_CONFIG + 1)
        .read_to_string(&mut json)?;
    if json.len() as u64 > MAX_CONFIG {
        return Err(io::Error::other("configuration exceeds size limit"));
    }
    parse_configuration(&json)
}

fn parse_configuration(json: &str) -> io::Result<Configuration> {
    let config: Configuration = parse_strict_json(json).map_err(io::Error::other)?;
    let release_id = &config.release_id;
    if config.security_domain_id == [0; 32]
        || release_id.is_empty()
        || release_id.len() > 64
        || !release_id.as_bytes()[0].is_ascii_alphanumeric()
        || !release_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(io::Error::other("invalid security domain or release ID"));
    }
    if matches!(&config.deployment, Deployment::Rotate { previous, .. } if previous.epoch == u64::MAX)
    {
        return Err(io::Error::other("custody epoch exhausted"));
    }
    Ok(config)
}

#[cfg(test)]
#[path = "../../tests/unit/nitro_configuration.rs"]
mod tests;
