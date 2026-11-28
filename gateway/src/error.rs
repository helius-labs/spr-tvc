use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Every failure the gateway returns, as an RFC 9457 problem:
/// `{"title", "status", "detail", "code"}`, where `code` is the variant name.
///
/// The edge proxy re-sends any 5xx up to twice. A failure after the request
/// reached the enclave or Turnkey is a 424, never a 5xx.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    thiserror::Error,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::VariantNames,
)]
pub enum ApiError {
    #[error("the body is not the JSON this endpoint takes")]
    InvalidJson,

    #[error("the request did not carry valid origin authentication")]
    OriginAuthRequired,
    #[error("the request names no valid project")]
    ProjectRequired,
    #[error("the request carries no Helius API key")]
    ApiKeyRequired,
    #[error("Helius does not know this API key")]
    ApiKeyInvalid,
    #[error("the API key's project cannot use WaaS: its plan, or the WaaS rollout")]
    WaasNotEnabled,

    #[error("no such endpoint")]
    NotFound,
    #[error("an operation with this ciphertext is still running")]
    OperationInProgress,
    #[error("the body is too large")]
    RequestTooLarge,
    #[error("too many requests in flight")]
    TooManyInFlight,

    #[error("the enclave did not answer")]
    EnclaveUnavailable,
    #[error("the enclave's answer is malformed")]
    InvalidEnclaveAnswer,
    #[error("the enclave's answer is too large")]
    UpstreamResponseTooLarge,
    #[error("Turnkey has no Boot Proof for the replica that answered")]
    BootProofUnavailable,
    #[error("Turnkey did not answer")]
    TurnkeyUnavailable,
    #[error("Turnkey refused this gateway's API key")]
    TurnkeyUnauthorized,
    #[error("Turnkey rate-limited this gateway")]
    TurnkeyRateLimited,
    #[error("the replay guard did not answer")]
    ReplayGuardUnavailable,
    #[error("the API key could not be checked")]
    ApiKeyLookupUnavailable,
}

/// An RFC 9457 problem; `type` is omitted, so it is `about:blank`.
#[derive(Serialize, utoipa::ToSchema)]
pub struct Problem {
    /// The HTTP status phrase.
    #[schema(value_type = String)]
    title: &'static str,
    status: u16,
    detail: String,
    /// What went wrong, for a program to act on.
    #[schema(value_type = String)]
    code: &'static str,
}

const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const RETRY_AFTER_SECS: HeaderValue = HeaderValue::from_static("1");

impl ApiError {
    #[inline]
    pub fn code(self) -> &'static str {
        self.into()
    }

    pub const fn status(self) -> StatusCode {
        match self {
            Self::InvalidJson => StatusCode::BAD_REQUEST,
            Self::OriginAuthRequired
            | Self::ProjectRequired
            | Self::ApiKeyRequired
            | Self::ApiKeyInvalid => StatusCode::UNAUTHORIZED,
            Self::WaasNotEnabled => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::OperationInProgress => StatusCode::CONFLICT,
            Self::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::TooManyInFlight => StatusCode::TOO_MANY_REQUESTS,
            Self::EnclaveUnavailable
            | Self::InvalidEnclaveAnswer
            | Self::UpstreamResponseTooLarge
            | Self::BootProofUnavailable
            | Self::TurnkeyUnavailable
            | Self::TurnkeyUnauthorized
            | Self::TurnkeyRateLimited
            | Self::ReplayGuardUnavailable
            | Self::ApiKeyLookupUnavailable => StatusCode::FAILED_DEPENDENCY,
        }
    }

    /// A failure worth retrying soon with the same request.
    const fn retry_after(self) -> Option<HeaderValue> {
        match self {
            Self::TooManyInFlight | Self::OperationInProgress => Some(RETRY_AFTER_SECS),
            _ => None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let problem = Problem {
            title: status.canonical_reason().unwrap_or("Error"),
            status: status.as_u16(),
            detail: self.to_string(),
            code: self.code(),
        };
        let mut response = (status, Json(problem)).into_response();
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, PROBLEM_JSON);
        if let Some(retry_after) = self.retry_after() {
            headers.insert(header::RETRY_AFTER, retry_after);
        }
        response
    }
}

#[cfg(test)]
#[path = "../tests/unit/public_errors.rs"]
mod tests;
