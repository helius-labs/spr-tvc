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
use spr_tvc_protocol::{EncryptedRequest, QosPingRequest, WalletDescriptor};
use tower_http::set_header::SetResponseHeaderLayer;
use utoipa::ToSchema;

use crate::api_keys::ApiKeys;
use crate::config::Config;
use crate::enrollment::{Enrollment, EnrollmentRequest};
use crate::error::ApiError;
use crate::error::Problem;
use crate::json::ApiJson;
use crate::limits::InFlightLimiter;
use crate::openapi::PingRequest;
use crate::project::Caller;
use crate::provisioner::{self, Provisioner};
use crate::replay::{Claim, Outcome, ReplayLedger};
use crate::turnkey::{CallShare, ClaimedWallet, Turnkey};
use crate::upstream::Enclave;
use crate::wallet_grant::WalletGrants;

pub const ROUTE_PREFIX: &str = "/v1/private-wallet";
pub const DECRYPTION_SERVICE_PREFIX: &str = "/v1/decryption";
/// Marks an `/operations` answer that repeats an earlier request's outcome.
pub const IDEMPOTENT_REPLAYED: HeaderName = HeaderName::from_static("idempotent-replayed");

pub struct AppState {
    pub origin_auth_header: String,
    pub api_keys: ApiKeys,
    pub enclave: Enclave,
    /// Present when `decryption_service` is configured for this network.
    pub decryption_enclave: Option<Enclave>,
    pub turnkey: Turnkey,
    pub provisioner: Provisioner,
    pub enrollment: Enrollment,
    pub wallet_grants: WalletGrants,
    pub limiter: InFlightLimiter,
    pub replay: ReplayLedger,
}

impl AppState {
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        let decryption_enclave = config
            .decryption_service
            .as_ref()
            .map(|decryption| {
                let mut enclave = config.enclave.clone();
                enclave.base_url = decryption.enclave.base_url.clone();
                Enclave::new(enclave)
            })
            .transpose()?;
        Ok(Self {
            origin_auth_header: config.origin_auth_header.clone(),
            api_keys: ApiKeys::new(&config.dev_api)?,
            enclave: Enclave::new(config.enclave.clone())?,
            decryption_enclave,
            turnkey: Turnkey::new(&config.turnkey)?,
            provisioner: Provisioner::new(&config.provisioning, config.network)?,
            enrollment: Enrollment::new(config.network, &config.enrollment.domains),
            wallet_grants: WalletGrants::new(&config.wallet_grant)?,
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
    let private_wallet = Router::new()
        .route("/session", post(session))
        .route("/enroll", post(enroll))
        .route("/operations", post(operations));
    let mut router = Router::new()
        .route("/health", get(health))
        .nest(ROUTE_PREFIX, private_wallet);
    if state.decryption_enclave.is_some() {
        let decryption_service = Router::new()
            .route("/session", post(decryption_session))
            .route("/operations", post(decryption_operations));
        router = router.nest(DECRYPTION_SERVICE_PREFIX, decryption_service);
    }
    router
        .fallback(not_found)
        .layer(middleware::from_fn(track))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .with_state(state)
}

/// The enclave's discovery document, its answer to the client's encrypted
/// ping, and the Boot Proof of the replica that answered.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Session {
    /// The enclave's `ServiceInfo`.
    #[schema(value_type = Object)]
    info: Box<RawValue>,
    /// The enclave's `QosPingResponse`.
    #[schema(value_type = Object)]
    ping: Box<RawValue>,
    /// Turnkey's Boot Proof for the replica that signed `ping`.
    #[schema(value_type = Object)]
    boot_proof: Box<RawValue>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct Enrolled {
    /// The `WalletDescriptor` for the enrolled client key, signed with the
    /// provisioning key. The client sends it with every operation.
    #[schema(value_type = Object)]
    descriptor: WalletDescriptor,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Operation {
    /// A `WalletDescriptor` this gateway enrolled.
    #[schema(value_type = Object)]
    descriptor: WalletDescriptor,
    /// The enclave's `EncryptedRequest`, without `wallet_grant`.
    #[schema(value_type = Object)]
    request: EncryptedRequest,
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

/// Open a session
///
/// Discovery, the enclave's answer to the ping and the Boot Proof of the
/// replica that answered, for the client to verify.
#[utoipa::path(
    post,
    path = "/v1/private-wallet/session",
    tag = "Private wallet",
    request_body = PingRequest,
    responses(
        (status = 200, description = "The evidence to verify", body = Session),
        (status = "4XX", description = "Refused, or the enclave or Turnkey did not answer", body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(crate) async fn session(
    State(state): State<Arc<AppState>>,
    Caller(project): Caller,
    ApiJson(ping): ApiJson<QosPingRequest>,
) -> Result<Response, ApiError> {
    let _permit = state.limiter.try_acquire(&project)?;
    let (info, ping) = tokio::try_join!(state.enclave.info(), state.enclave.ping(&ping))?;
    if !info.is_success() {
        return Ok(info.into_response());
    }
    if !ping.is_success() {
        return Ok(ping.into_response());
    }
    let boot_proof = state
        .turnkey
        .boot_proof(&app_proof_key(&ping.body)?, CallShare::Project(&project))
        .await?;
    Ok(Json(Session {
        info: raw_json(&info.body)?,
        ping: raw_json(&ping.body)?,
        boot_proof: raw_json(&boot_proof)?,
    })
    .into_response())
}

/// Enroll a client key
///
/// A descriptor for the enrollment's client key, once the wallet owner's
/// signature and the wallet's ownership check out. Enrolling again answers
/// the same descriptor.
#[utoipa::path(
    post,
    path = "/v1/private-wallet/enroll",
    tag = "Private wallet",
    request_body = EnrollmentRequest,
    responses(
        (status = 200, description = "The descriptor for the client key", body = Enrolled),
        (status = "4XX", description = "Refused, or the enclave or Turnkey did not answer", body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(crate) async fn enroll(
    State(state): State<Arc<AppState>>,
    Caller(project): Caller,
    ApiJson(request): ApiJson<EnrollmentRequest>,
) -> Result<Json<Enrolled>, ApiError> {
    let now_ms = clock_ms()?;
    state.provisioner.check_current(now_ms)?;
    let input = state.enrollment.verify(&request, now_ms)?;
    state
        .wallet_grants
        .check_client_key(&input.client_public_key)?;
    let _permit = state.limiter.try_acquire(&project)?;
    let wallet = ClaimedWallet {
        organization_id: &input.organization_id,
        wallet_id: &input.turnkey_wallet_id,
        address: &input.solana_address,
    };
    state.turnkey.verify_ownership(&project, &wallet).await?;
    let descriptor = state.provisioner.sign(&input)?;
    Ok(Json(Enrolled { descriptor }))
}

/// Open a decryption-service session
///
/// Discovery, the enclave's answer to the ping and the Boot Proof of the
/// replica that answered. No enrollment: the decryption service authorizes
/// with a Solana signature on decrypt requests.
#[utoipa::path(
    post,
    path = "/v1/decryption/session",
    tag = "Decryption service",
    request_body = PingRequest,
    responses(
        (status = 200, description = "The evidence to verify", body = Session),
        (status = "4XX", description = "Refused, or the enclave or Turnkey did not answer", body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(crate) async fn decryption_session(
    State(state): State<Arc<AppState>>,
    Caller(project): Caller,
    ApiJson(ping): ApiJson<QosPingRequest>,
) -> Result<Response, ApiError> {
    let enclave = state
        .decryption_enclave
        .as_ref()
        .ok_or(ApiError::NotFound)?;
    let _permit = state.limiter.try_acquire(&project)?;
    let (info, ping) = tokio::try_join!(enclave.info(), enclave.ping(&ping))?;
    if !info.is_success() {
        return Ok(info.into_response());
    }
    if !ping.is_success() {
        return Ok(ping.into_response());
    }
    let boot_proof = state
        .turnkey
        .boot_proof(&app_proof_key(&ping.body)?, CallShare::Project(&project))
        .await?;
    Ok(Json(Session {
        info: raw_json(&info.body)?,
        ping: raw_json(&ping.body)?,
        boot_proof: raw_json(&boot_proof)?,
    })
    .into_response())
}

/// The enclave's `EncryptedRequest` without a wallet grant (OpenAPI shape).
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
/// Forwards the client's encrypted request as it is (no wallet grant) and
/// returns the Boot Proof of the replica that answered. A resent request gets
/// the first request's answer, marked `Idempotent-Replayed`.
#[utoipa::path(
    post,
    path = "/v1/decryption/operations",
    tag = "Decryption service",
    request_body(content = DecryptionEncryptedRequest, description = "The enclave's EncryptedRequest, without wallet_grant"),
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
    let enclave = state
        .decryption_enclave
        .as_ref()
        .ok_or(ApiError::NotFound)?;
    if request.wallet_grant.is_some() {
        return Err(ApiError::WalletGrantNotAllowed);
    }
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
    let outcome = enclave.operations(&request).await;
    state.replay.record(key, &outcome).await;
    Ok(answer(&state, outcome).await)
}

/// Run an operation
///
/// Forwards the client's encrypted request with a wallet grant this gateway
/// signs for the descriptor's client key and the caller's project. A resent
/// request gets the first request's answer, marked `Idempotent-Replayed`.
#[utoipa::path(
    post,
    path = "/v1/private-wallet/operations",
    tag = "Private wallet",
    request_body = Operation,
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
pub(crate) async fn operations(
    State(state): State<Arc<AppState>>,
    Caller(project): Caller,
    ApiJson(Operation {
        descriptor,
        mut request,
    }): ApiJson<Operation>,
) -> Result<Response, ApiError> {
    state.provisioner.verify(&descriptor, clock_ms()?)?;
    let [client] = descriptor.allowed_clients.as_slice() else {
        return Err(ApiError::InvalidDescriptor);
    };
    state
        .wallet_grants
        .check_client_key(&client.client_public_key)?;
    let _permit = state.limiter.try_acquire(&project)?;
    let key = match state
        .replay
        .claim(ROUTE_PREFIX, &project, &request.ciphertext)
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
    let granted = async {
        state
            .turnkey
            .verify_sub_org_project(&project, &descriptor.turnkey_organization_id)
            .await?;
        state
            .wallet_grants
            .issue(&project, &descriptor, clock_ms()?)
    }
    .await;
    let grant = match granted {
        Ok(grant) => grant,
        Err(error) => {
            state.replay.release(key).await;
            return Err(error);
        }
    };
    request.wallet_grant = Some(grant);
    let outcome = state.enclave.operations(&request).await;
    state.replay.record(key, &outcome).await;
    Ok(answer(&state, outcome).await)
}

/// The client's answer to an enclave outcome: a success with the Boot Proof
/// of the replica that answered, the enclave's refusal as it is, or the
/// failure. The enclave's work is done, Bootstrap's with the owner's
/// approval, so the lookup takes no slot of the project's Turnkey share,
/// only of the shared bound.
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
    if let Some(path) = matched.strip_prefix(ROUTE_PREFIX) {
        return match path {
            "/session" => "session",
            "/enroll" => "enroll",
            "/operations" => "operations",
            _ => "other",
        };
    }
    match matched.strip_prefix(DECRYPTION_SERVICE_PREFIX) {
        Some("/session") => "decryption_session",
        Some("/operations") => "decryption_operations",
        Some(_) | None => "other",
    }
}

fn clock_ms() -> Result<u64, ApiError> {
    provisioner::now_ms().map_err(|error| {
        tracing::error!(%error, "system clock unavailable");
        ApiError::ClockUnavailable
    })
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
