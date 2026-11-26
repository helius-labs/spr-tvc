use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{DefaultBodyLimit, MatchedPath, Request, State};
use axum::http::{HeaderName, HeaderValue, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use cadence_macros::statsd_time;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use spr_tvc_wire::EncryptedRequest;
use tower_http::set_header::SetResponseHeaderLayer;
use utoipa::ToSchema;

use crate::api_keys::ApiKeys;
use crate::config::Config;
use crate::error::ApiError;
use crate::error::Problem;
use crate::json::ApiJson;
use crate::limits::InFlightLimiter;
use crate::project::Caller;
use crate::replay::{Claim, Outcome, ReplayLedger};
use crate::turnkey::{CallShare, Turnkey};
use crate::upstream::Enclave;

pub const DECRYPTION_SERVICE_PREFIX: &str = "/v1/decryption";
/// Marks an `/operations` answer that repeats an earlier request's outcome.
pub const IDEMPOTENT_REPLAYED: HeaderName = HeaderName::from_static("idempotent-replayed");

pub struct AppState {
    pub origin_auth_header: String,
    pub api_keys: ApiKeys,
    pub enclave: Enclave,
    pub turnkey: Turnkey,
    pub limiter: InFlightLimiter,
    pub replay: ReplayLedger,
}

impl AppState {
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        Ok(Self {
            origin_auth_header: config.origin_auth_header.clone(),
            api_keys: ApiKeys::new(&config.dev_api)?,
            enclave: Enclave::new(config.enclave.clone())?,
            turnkey: Turnkey::new(&config.turnkey)?,
            limiter: InFlightLimiter::new(
                config.enclave.max_in_flight_per_project,
                "enclave.in_flight_rejected",
            ),
            replay: ReplayLedger::connect(
                Duration::from_secs(config.enclave.replay_window_secs),
                config.enclave.replay_max_entries,
                config.enclave.replay_redis_url.as_deref(),
            )
            .await?,
        })
    }
}

pub fn router(state: Arc<AppState>, max_body_bytes: usize) -> Router {
    let decryption_service = Router::new().route("/operations", post(decryption_operations));
    Router::new()
        .route("/health", get(health))
        .nest(DECRYPTION_SERVICE_PREFIX, decryption_service)
        .fallback(not_found)
        .layer(middleware::from_fn(track))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .with_state(state)
}

/// The enclave's encrypted response and the Boot Proof of the replica that
/// answered.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Operated {
    /// The enclave's `EncryptedResponse`.
    #[schema(value_type = Object)]
    response: Box<RawValue>,
    /// Turnkey's Boot Proof for the replica that signed `response`.
    #[schema(value_type = Object)]
    boot_proof: Box<RawValue>,
}

/// The app proof an enclave answer carries, as far as locating its Boot Proof.
#[derive(Deserialize)]
struct AppProofCarrier {
    tvc_app_proof: AppProofKey,
}

#[derive(Deserialize)]
struct AppProofKey {
    public_key: String,
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn not_found() -> ApiError {
    ApiError::NotFound
}

/// The enclave's `EncryptedRequest` (OpenAPI shape).
#[derive(ToSchema)]
#[allow(dead_code)]
struct DecryptionEncryptedRequest {
    version: u8,
    quorum_key_id: String,
    /// Decimal string of the quorum key epoch.
    quorum_key_epoch: String,
    /// Hex ciphertext.
    ciphertext: String,
}

/// Run a decryption-service operation
///
/// Forwards the client's encrypted request as it is and returns the Boot
/// Proof of the replica that answered. A resent request gets the first
/// request's answer, marked `Idempotent-Replayed`.
#[utoipa::path(
    post,
    path = "/v1/decryption/operations",
    tag = "Decryption service",
    request_body = DecryptionEncryptedRequest,
    responses(
        (
            status = 200,
            description = "The enclave's answer and its evidence",
            body = Operated,
            headers(("Idempotent-Replayed" = String, description = "`true` when the answer repeats an earlier request's")),
        ),
        (status = "4XX", description = "Refused, or the enclave or Turnkey did not answer", body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(crate) async fn decryption_operations(
    State(state): State<Arc<AppState>>,
    Caller(project): Caller,
    ApiJson(request): ApiJson<EncryptedRequest>,
) -> Result<Response, ApiError> {
    let _permit = state.limiter.try_acquire(&project)?;
    let key = match state
        .replay
        .claim(DECRYPTION_SERVICE_PREFIX, &project, &request.ciphertext)
        .await?
    {
        Claim::New(key) => key,
        Claim::Answered(outcome) => {
            let mut response = answer(&state, outcome).await;
            response
                .headers_mut()
                .insert(IDEMPOTENT_REPLAYED, HeaderValue::from_static("true"));
            return Ok(response);
        }
    };
    let outcome = state.enclave.operations(&request).await;
    state.replay.record(key, &outcome).await;
    Ok(answer(&state, outcome).await)
}

/// The client's answer to an enclave outcome: a success with the Boot Proof
/// of the replica that answered, the enclave's refusal as it is, or the
/// failure. The enclave's work is done, so the lookup takes no slot of the
/// project's Turnkey share, only of the shared bound.
async fn answer(state: &AppState, outcome: Outcome) -> Response {
    let answered = async {
        let forwarded = outcome?;
        if !forwarded.is_success() {
            return Ok(forwarded.into_response());
        }
        let boot_proof = state
            .turnkey
            .boot_proof(&app_proof_key(&forwarded.body)?, CallShare::Shared)
            .await?;
        Ok(Json(Operated {
            response: raw_json(&forwarded.body)?,
            boot_proof: raw_json(&boot_proof)?,
        })
        .into_response())
    }
    .await;
    answered.unwrap_or_else(|error: ApiError| error.into_response())
}

async fn track(request: Request, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("unmatched", |path| route_name(path.as_str()));
    let started = Instant::now();
    let response = next.run(request).await;
    let status = response.status();
    statsd_time!("request.latency", started.elapsed(), "route" => route, "status" => status.as_str());
    response
}

fn route_name(matched: &str) -> &'static str {
    match matched.strip_prefix(DECRYPTION_SERVICE_PREFIX) {
        Some("/operations") => "decryption_operations",
        Some(_) | None => "other",
    }
}

/// The Boot Proof lookup key of the replica that signed an enclave answer.
fn app_proof_key(body: &[u8]) -> Result<String, ApiError> {
    serde_json::from_slice::<AppProofCarrier>(body)
        .map(|carrier| carrier.tvc_app_proof.public_key)
        .map_err(|_| ApiError::InvalidEnclaveAnswer)
}

fn raw_json(body: &[u8]) -> Result<Box<RawValue>, ApiError> {
    serde_json::from_slice(body).map_err(|_| ApiError::InvalidEnclaveAnswer)
}

#[cfg(test)]
#[path = "../tests/unit/routing_and_authorization.rs"]
mod tests;
