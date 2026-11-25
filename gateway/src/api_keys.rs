//! Helius API keys a direct caller sends, resolved to their project by Helius
//! dev-api's `GET /waas/config`. dev-api answers 401 for an unknown key and
//! 403 for a project without the WaaS add-on.

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use cadence_macros::statsd_count;
use reqwest::StatusCode;
use reqwest::redirect::Policy;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::config::DevApiConfig;
use crate::error::ApiError;
use crate::project::ProjectId;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const REJECTION_TTL: Duration = Duration::from_secs(30);
const CACHE_CAPACITY: usize = 100_000;
const MAX_API_KEY_LEN: usize = 64;

/// `GET /waas/config`, as far as the project.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WaasConfig {
    project_id: Option<String>,
}

/// A key's project, or why dev-api refused it: `ApiKeyInvalid` or `WaasNotEnabled`.
type Resolved = Result<ProjectId, ApiError>;

pub struct ApiKeys {
    http: reqwest::Client,
    waas_config_url: String,
    project_ttl: Duration,
    /// Keyed by the SHA-256 of the API key.
    cache: Mutex<HashMap<[u8; 32], (Resolved, Instant)>>,
}

impl ApiKeys {
    pub fn new(config: &DevApiConfig) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .redirect(Policy::none())
            .timeout(LOOKUP_TIMEOUT)
            .build()?;
        Ok(Self {
            http,
            waas_config_url: format!("{}/waas/config", config.base_url),
            project_ttl: Duration::from_secs(config.project_cache_secs),
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The project `api_key` belongs to.
    pub async fn project(&self, api_key: &str) -> Result<ProjectId, ApiError> {
        if !is_api_key(api_key) {
            statsd_count!("api_key.rejected", 1, "reason" => "shape");
            return Err(ApiError::ApiKeyInvalid);
        }
        let digest: [u8; 32] = Sha256::digest(api_key.as_bytes()).into();
        let resolved = match self.cached(&digest) {
            Some(resolved) => {
                statsd_count!("api_key.cache_hit", 1);
                resolved
            }
            None => {
                let resolved = self.fetch(api_key).await?;
                self.store(digest, resolved.clone());
                resolved
            }
        };
        if let Err(refused) = resolved {
            statsd_count!("api_key.rejected", 1, "reason" => refused.code());
        }
        resolved
    }

    async fn fetch(&self, api_key: &str) -> Result<Resolved, ApiError> {
        let response = self
            .http
            .get(&self.waas_config_url)
            .header("x-api-key", api_key)
            .send()
            .await
            .map_err(lookup_failed)?;
        match response.status() {
            StatusCode::UNAUTHORIZED => return Ok(Err(ApiError::ApiKeyInvalid)),
            StatusCode::FORBIDDEN => return Ok(Err(ApiError::WaasNotEnabled)),
            status if !status.is_success() => return Err(lookup_failed(status)),
            _ => {}
        }
        let config: WaasConfig = response.json().await.map_err(lookup_failed)?;
        let project = config.project_id.as_deref().and_then(ProjectId::parse);
        project
            .map(Ok)
            .ok_or_else(|| lookup_failed("the answer names no valid projectId"))
    }

    fn cached(&self, digest: &[u8; 32]) -> Option<Resolved> {
        let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        let (resolved, fetched_at) = cache.get(digest)?;
        let ttl = if resolved.is_ok() {
            self.project_ttl
        } else {
            REJECTION_TTL
        };
        (fetched_at.elapsed() < ttl).then(|| resolved.clone())
    }

    fn store(&self, digest: [u8; 32], resolved: Resolved) {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= CACHE_CAPACITY {
            cache.clear();
        }
        cache.insert(digest, (resolved, Instant::now()));
    }
}

fn lookup_failed(reason: impl Display) -> ApiError {
    tracing::warn!(%reason, "api key lookup failed");
    statsd_count!("api_key.lookup_failed", 1);
    ApiError::ApiKeyLookupUnavailable
}

/// A Helius API key is a UUID; anything else is refused before the lookup.
#[inline]
fn is_api_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_API_KEY_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(test)]
#[path = "../tests/unit/api_key_resolution.rs"]
mod tests;
