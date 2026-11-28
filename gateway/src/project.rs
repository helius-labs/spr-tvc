use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use cadence_macros::statsd_count;
use subtle::ConstantTimeEq;

use crate::app::AppState;
use crate::error::ApiError;

pub const PROJECT_ID_HEADER: &str = "x-helius-project-id";
pub const API_KEY_HEADER: &str = "x-api-key";
const API_KEY_PARAM: &str = "api-key=";
const MAX_PROJECT_ID_LEN: usize = 64;

/// The Helius project the caller's API key belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProjectId(Arc<str>);

impl ProjectId {
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        let valid = !value.is_empty()
            && value.len() <= MAX_PROJECT_ID_LEN
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        valid.then(|| Self(Arc::from(value)))
    }
}

/// The project a request is made for. A request with an `Authorization`
/// header came through the edge proxy, which sends its origin credential and
/// the project. Any other carries a Helius API key, as the `api-key` query
/// parameter or the `X-Api-Key` header, which the gateway resolves itself.
pub struct Caller(pub ProjectId);

impl FromRequestParts<Arc<AppState>> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        if let Some(presented) = parts.headers.get(AUTHORIZATION) {
            return edge_proxy_project(parts, presented.as_bytes(), state).map(Self);
        }
        let api_key = api_key(parts).ok_or(ApiError::ApiKeyRequired)?;
        state.api_keys.project(api_key).await.map(Self)
    }
}

fn edge_proxy_project(
    parts: &Parts,
    presented: &[u8],
    state: &AppState,
) -> Result<ProjectId, ApiError> {
    if !bool::from(presented.ct_eq(state.origin_auth_header.as_bytes())) {
        statsd_count!("origin_auth_rejected", 1);
        return Err(ApiError::OriginAuthRequired);
    }
    parts
        .headers
        .get(PROJECT_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(ProjectId::parse)
        .ok_or(ApiError::ProjectRequired)
}

fn api_key(parts: &Parts) -> Option<&str> {
    if let Some(header) = parts.headers.get(API_KEY_HEADER) {
        return header.to_str().ok();
    }
    parts
        .uri
        .query()?
        .split('&')
        .find_map(|pair| pair.strip_prefix(API_KEY_PARAM))
}

#[cfg(test)]
#[path = "../tests/unit/project_identity.rs"]
mod tests;
