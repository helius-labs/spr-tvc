//! QOS startup, discovery, and HTTP routing.

use std::io;
use std::sync::Arc;
#[cfg(feature = "qos-runtime")]
use std::{fs, path::Path};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, Response};
use axum::response::IntoResponse;
use axum::Router;
#[cfg(feature = "qos-runtime")]
use qos_core::{
    protocol::services::boot::manifest::{canonical_json_hash, ManifestEnvelopeV2},
    EPHEMERAL_KEY_FILE, MANIFEST_FILE, QUORUM_FILE,
};
#[cfg(any(feature = "qos-runtime", feature = "local-dev", test))]
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
use crate::keys::NoteSeed;
use crate::operations;
use crate::request::sign_ephemeral_low_s;
use crate::wire::KeyPair;
#[cfg(feature = "qos-runtime")]
use crate::Release;

/// A running release: what it advertises and the QOS keys it answers with.
pub struct Service {
    pub(crate) info: ServiceInfo,
    pub(crate) ephemeral: KeyPair,
    pub(crate) quorum: KeyPair,
    pub(crate) note_seed: NoteSeed,
}

impl Service {
    #[cfg(any(feature = "local-dev", feature = "qos-runtime", test))]
    pub(crate) fn new(info: ServiceInfo, ephemeral: P256Pair, quorum: P256Pair) -> Self {
        let note_seed = NoteSeed::from_quorum(&quorum);
        Self {
            info,
            ephemeral: KeyPair::Qos(ephemeral),
            quorum: KeyPair::Qos(quorum),
            note_seed,
        }
    }

    /// Loads the QOS keys from the canonical paths and binds discovery to the approved manifest.
    #[cfg(feature = "qos-runtime")]
    pub fn load(release: Release) -> io::Result<Self> {
        Self::load_from(
            release,
            Path::new(EPHEMERAL_KEY_FILE),
            Path::new(QUORUM_FILE),
            Path::new(MANIFEST_FILE),
        )
    }

    #[cfg(feature = "qos-runtime")]
    fn load_from(
        release: Release,
        ephemeral_path: &Path,
        quorum_path: &Path,
        manifest_path: &Path,
    ) -> io::Result<Self> {
        let ephemeral = P256Pair::from_hex_file(ephemeral_path)
            .map_err(|_| io::Error::other("failed to load QOS ephemeral key"))?;
        let quorum = P256Pair::from_hex_file(quorum_path)
            .map_err(|_| io::Error::other("failed to load QOS quorum key"))?;
        let envelope: ManifestEnvelopeV2 = serde_json::from_slice(&fs::read(manifest_path)?)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let manifest = envelope.manifest;
        if manifest.namespace.quorum_key != quorum.public_key().to_bytes() {
            return Err(io::Error::other(
                "QOS quorum key does not match the approved manifest",
            ));
        }
        let info = release.service_info(
            canonical_json_hash(&manifest),
            manifest.pivot.hash,
            quorum.public_key().to_bytes(),
        );
        Ok(Self::new(info, ephemeral, quorum))
    }
}

pub(crate) fn router(service: Arc<Service>) -> Router {
    Router::new().fallback(dispatch).with_state(service)
}

pub(crate) async fn dispatch(
    State(service): State<Arc<Service>>,
    request: Request<Body>,
) -> Response<Body> {
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
        ("POST", "/v1/ping") => handle_ping(&service, &body),
        ("POST", "/v1/operations") => operations::handle(&service, &body),
        ("GET", "/health") => match jcs_serialize(&HealthResponse {
            status: HealthStatus::Healthy,
        }) {
            Ok(body) => http::ok(body),
            Err(_) => PublicError::Unavailable.into_response(),
        },
        ("GET", "/v1/info") => match jcs_serialize(&service.info) {
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
            public_key: service.ephemeral.public_bytes(),
            proof_payload: proof_payload.to_owned(),
            signature,
        },
    };
    match jcs_serialize(&response) {
        Ok(body) => http::ok(body),
        Err(_) => PublicError::Unavailable.into_response(),
    }
}

/// Serves the enclave until SIGINT or SIGTERM.
pub async fn serve(listener: tokio::net::TcpListener, service: Service) -> io::Result<()> {
    axum::serve(listener, router(Arc::new(service)))
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

#[cfg(all(test, feature = "qos-runtime"))]
#[path = "../tests/unit/qos_startup.rs"]
mod startup_tests;
