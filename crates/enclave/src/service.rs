//! The routes every application serves around its own operations.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, Response};
use axum::response::IntoResponse;
use axum::Router;
use qos_core::handles::Handles;
use qos_core::{EPHEMERAL_KEY_FILE, MANIFEST_FILE, PIVOT_FILE, QUORUM_FILE};
use qos_p256::P256Pair;
use spr_tvc_protocol::constants::{
    API_VERSION, MAX_ENCRYPTED_REQUEST_BYTES, TVC_APP_PROOF_SCHEME, TVC_QOS_PING_PROOF_TYPE,
};
use spr_tvc_protocol::encoding::{is_rfc8785, jcs_serialize};
use spr_tvc_protocol::types::{
    parse_qos_ping_challenge, parse_qos_ping_request, AppProof, HealthResponse, HealthStatus,
    QosPingResponse, ServiceInfo,
};

use crate::http::{self, PublicError};
use crate::request::sign_ephemeral_low_s;
use crate::{App, Release};

/// A running release: what it advertises and the QOS keys it answers with.
#[derive(Clone)]
pub struct Service {
    pub info: Arc<ServiceInfo>,
    pub ephemeral: Arc<P256Pair>,
    pub quorum: Arc<P256Pair>,
}

impl Service {
    pub fn new(info: ServiceInfo, ephemeral: P256Pair, quorum: P256Pair) -> Self {
        Self {
            info: Arc::new(info),
            ephemeral: Arc::new(ephemeral),
            quorum: Arc::new(quorum),
        }
    }

    /// Loads the QOS keys from the canonical paths and binds discovery to the approved manifest.
    pub fn load(release: Release, app: &App) -> io::Result<Self> {
        Self::load_from(
            release,
            app,
            &Handles::new(
                EPHEMERAL_KEY_FILE.to_owned(),
                QUORUM_FILE.to_owned(),
                MANIFEST_FILE.to_owned(),
                PIVOT_FILE.to_owned(),
            ),
        )
    }

    fn load_from(release: Release, app: &App, handles: &Handles) -> io::Result<Self> {
        let ephemeral = handles
            .get_ephemeral_key()
            .map_err(|_| io::Error::other("failed to load QOS ephemeral key"))?;
        let quorum = handles
            .get_quorum_key()
            .map_err(|_| io::Error::other("failed to load QOS quorum key"))?;
        let envelope = handles
            .get_manifest_envelope()
            .map_err(|_| io::Error::other("failed to load QOS manifest"))?;

        let manifest_digest = envelope.manifest_hash();
        let executable_digest = *envelope.pivot_hash();
        if envelope.manifest().namespace().quorum_key != quorum.public_key().to_bytes() {
            return Err(io::Error::other(
                "QOS quorum key does not match the approved manifest",
            ));
        }
        let info =
            release.service_info(app, manifest_digest, executable_digest, &quorum, &ephemeral);
        Ok(Self::new(info, ephemeral, quorum))
    }
}

#[derive(Clone)]
struct Routes<H> {
    service: Service,
    operations: H,
}

/// `operations` answers `POST /v1/operations`.
pub fn router<H, F>(service: Service, operations: H) -> Router
where
    H: Fn(Bytes) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Response<Body>> + Send + 'static,
{
    Router::new().fallback(dispatch::<H, F>).with_state(Routes {
        service,
        operations,
    })
}

/// `/v1/ping` and `/v1/operations` take JSON posts. `/health` is process
/// readiness only and MUST NOT include release, key, or deployment
/// identifiers; `/v1/info` is discovery data, not a trust root.
async fn dispatch<H, F>(State(routes): State<Routes<H>>, request: Request<Body>) -> Response<Body>
where
    H: Fn(Bytes) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Response<Body>> + Send + 'static,
{
    let service = &routes.service;
    let (parts, body) = request.into_parts();
    let body_limit = usize::try_from(
        service
            .info
            .max_encrypted_request_bytes
            .min(MAX_ENCRYPTED_REQUEST_BYTES),
    )
    .unwrap_or(usize::MAX);
    let Ok(body) = to_bytes(body, body_limit).await else {
        return PublicError::RequestTooLarge.into_response();
    };

    match (parts.method.as_str(), parts.uri.path()) {
        ("POST", "/v1/ping" | "/v1/operations") if !has_json_content_type(&parts.headers) => {
            PublicError::InvalidRequest.into_response()
        }
        ("POST", "/v1/ping") => handle_ping(service, &body),
        ("POST", "/v1/operations") => (routes.operations)(body).await,
        ("GET", "/health") => match jcs_serialize(&HealthResponse {
            status: HealthStatus::Healthy,
        }) {
            Ok(body) => http::ok(body),
            Err(_) => PublicError::Unavailable.into_response(),
        },
        ("GET", "/v1/info") => match jcs_serialize(&*service.info) {
            Ok(body) => http::ok(body),
            Err(_) => PublicError::InvalidRequest.into_response(),
        },
        (_, "/v1/ping" | "/v1/operations" | "/health" | "/v1/info") => {
            PublicError::MethodNotAllowed.into_response()
        }
        _ => PublicError::NotFound.into_response(),
    }
}

fn has_json_content_type(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim() == "application/json")
}

fn handle_ping(service: &Service, body: &[u8]) -> Response<Body> {
    let invalid = || PublicError::InvalidRequest.into_response();
    let Ok(body) = std::str::from_utf8(body) else {
        return invalid();
    };
    let Ok(request) = parse_qos_ping_request(body) else {
        return invalid();
    };
    if request.version != API_VERSION {
        return invalid();
    }
    let Ok(plaintext) = service.quorum.decrypt(&request.encrypted_challenge) else {
        return invalid();
    };
    let Ok(proof_payload) = std::str::from_utf8(&plaintext) else {
        return invalid();
    };
    let Ok(challenge) = parse_qos_ping_challenge(proof_payload) else {
        return invalid();
    };
    if challenge.version != API_VERSION
        || challenge.r#type != TVC_QOS_PING_PROOF_TYPE
        || !is_rfc8785(proof_payload)
    {
        return invalid();
    }

    let Ok(signature) = sign_ephemeral_low_s(&service.ephemeral, proof_payload.as_bytes()) else {
        return PublicError::Unavailable.into_response();
    };
    let response = QosPingResponse {
        version: API_VERSION,
        tvc_app_proof: AppProof {
            scheme: TVC_APP_PROOF_SCHEME.to_owned(),
            public_key: service.ephemeral.public_key().to_bytes(),
            proof_payload: proof_payload.to_owned(),
            signature,
        },
    };
    match jcs_serialize(&response) {
        Ok(body) => http::ok(body),
        Err(_) => PublicError::Unavailable.into_response(),
    }
}

/// Serves `router` at `address` until SIGINT or SIGTERM, the signals QOS and a shell send.
pub async fn serve(address: SocketAddr, router: Router) -> io::Result<()> {
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
        })
        .await
}

#[cfg(test)]
#[path = "../tests/unit/http_and_ping.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/unit/qos_startup.rs"]
mod startup_tests;
