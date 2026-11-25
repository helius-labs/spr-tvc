use axum::body::Body;
use axum::http::{Request as HttpRequest, StatusCode};
use tower::ServiceExt;

use super::*;
use crate::config::EnclaveConfig;
use crate::project::{PROJECT_ID_HEADER, ProjectId};
use crate::replay::LocalLedger;

const ORIGIN_AUTH: &str = "Bearer gatekeeper-test";
const PROJECT: &str = "project-a";
const UNREACHABLE: &str = "http://127.0.0.1:9";

fn state() -> Arc<AppState> {
    crate::metrics::init_for_tests();
    let enclave = EnclaveConfig {
        base_url: UNREACHABLE.to_owned(),
        request_timeout_ms: 2_000,
        max_body_bytes: 4_096,
        max_in_flight_per_project: 4,
        replay_window_secs: 360,
        replay_max_entries: 1_000,
        replay_redis_url: None,
    };
    let enclave = Enclave::new(enclave).expect("test state did not build");
    Arc::new(AppState {
        origin_auth_header: ORIGIN_AUTH.to_owned(),
        api_keys: ApiKeys::for_tests(UNREACHABLE),
        enclave,
        turnkey: Turnkey::for_tests(UNREACHABLE),
        limiter: InFlightLimiter::new(4, "test.in_flight_rejected"),
        replay: ReplayLedger::Local(LocalLedger::new(Duration::from_secs(360), 1_000)),
    })
}

fn request(method: &str, path: &str, body: &str) -> HttpRequest<Body> {
    let built = HttpRequest::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, ORIGIN_AUTH)
        .header(PROJECT_ID_HEADER, PROJECT)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()));
    built.expect("test request did not build")
}

async fn call(state: &Arc<AppState>, request: HttpRequest<Body>) -> (StatusCode, String) {
    let response = match router(Arc::clone(state), 4_096).oneshot(request).await {
        Ok(response) => response,
        Err(infallible) => match infallible {},
    };
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 65_536)
        .await
        .expect("body did not read");
    let problem_code = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|problem| problem["code"].as_str().map(str::to_owned));
    (
        status,
        problem_code.unwrap_or_else(|| String::from_utf8_lossy(&body).into_owned()),
    )
}

fn operation(ciphertext: &str) -> String {
    serde_json::json!({
        "version": spr_tvc_wire::constants::API_VERSION,
        "quorum_key_id": "q",
        "quorum_key_epoch": "1",
        "ciphertext": ciphertext,
    })
    .to_string()
}

#[tokio::test]
async fn health_needs_no_credentials() {
    let state = state();
    let bare = HttpRequest::builder()
        .uri("/health")
        .body(Body::empty())
        .expect("test request did not build");
    assert_eq!(call(&state, bare).await.0, StatusCode::OK);
}

#[tokio::test]
async fn requests_without_gatekeepers_credential_or_project_are_refused() {
    let state = state();
    let mut forged = request("POST", "/v1/decryption/session", "{}");
    forged.headers_mut().insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer forged"),
    );
    assert_eq!(
        call(&state, forged).await,
        (StatusCode::UNAUTHORIZED, "OriginAuthRequired".to_owned())
    );
    let mut anonymous = request("POST", "/v1/decryption/session", "{}");
    anonymous.headers_mut().remove(PROJECT_ID_HEADER);
    assert_eq!(
        call(&state, anonymous).await,
        (StatusCode::UNAUTHORIZED, "ProjectRequired".to_owned())
    );
}

#[tokio::test]
async fn a_direct_request_needs_an_api_key_dev_api_resolves() {
    let state = state();
    let direct = |path: &str| {
        let mut request = request("POST", path, "{}");
        request.headers_mut().remove(header::AUTHORIZATION);
        request.headers_mut().remove(PROJECT_ID_HEADER);
        request
    };
    assert_eq!(
        call(&state, direct("/v1/decryption/session")).await,
        (StatusCode::UNAUTHORIZED, "ApiKeyRequired".to_owned())
    );
    assert_eq!(
        call(
            &state,
            direct("/v1/decryption/session?api-key=not%20a%20key")
        )
        .await,
        (StatusCode::UNAUTHORIZED, "ApiKeyInvalid".to_owned())
    );
    let unresolved = (
        StatusCode::FAILED_DEPENDENCY,
        "ApiKeyLookupUnavailable".to_owned(),
    );
    let key = "0b4a3a9e-5f7e-4b4f-9c1e-0d9f2a1b3c4d";
    assert_eq!(
        call(
            &state,
            direct(&format!("/v1/decryption/session?api-key={key}"))
        )
        .await,
        unresolved
    );
    let mut by_header = direct("/v1/decryption/session");
    by_header.headers_mut().insert(
        crate::project::API_KEY_HEADER,
        HeaderValue::from_static(key),
    );
    assert_eq!(call(&state, by_header).await, unresolved);
}

#[tokio::test]
async fn a_malformed_operation_is_refused() {
    let state = state();
    assert_eq!(
        call(&state, request("POST", "/v1/decryption/operations", "{}")).await,
        (StatusCode::BAD_REQUEST, "InvalidJson".to_owned())
    );
}

#[tokio::test]
async fn a_ciphertext_that_never_reached_the_enclave_can_be_resent() {
    let state = state();
    let operations =
        |body: String| call(&state, request("POST", "/v1/decryption/operations", &body));
    let unreachable = (
        StatusCode::FAILED_DEPENDENCY,
        "EnclaveUnavailable".to_owned(),
    );
    assert_eq!(operations(operation("abcd")).await, unreachable);
    assert_eq!(operations(operation("abcd")).await, unreachable);
}

#[tokio::test]
async fn a_session_takes_one_of_the_projects_in_flight_slots() {
    let state = state();
    let body = r#"{"version":1,"encrypted_challenge":"aa"}"#;
    let held: Vec<_> = (0..4)
        .map(|_| {
            state
                .limiter
                .try_acquire(&ProjectId::for_tests(PROJECT))
                .expect("a free slot")
        })
        .collect();
    assert_eq!(
        call(&state, request("POST", "/v1/decryption/session", body)).await,
        (StatusCode::TOO_MANY_REQUESTS, "TooManyInFlight".to_owned())
    );
    drop(held);
    assert_eq!(
        call(&state, request("POST", "/v1/decryption/session", body)).await,
        (
            StatusCode::FAILED_DEPENDENCY,
            "EnclaveUnavailable".to_owned()
        )
    );
}

#[tokio::test]
async fn oversized_enclave_bodies_and_other_routes_are_refused() {
    let state = state();
    let oversized = "x".repeat(8_192);
    assert_eq!(
        call(
            &state,
            request("POST", "/v1/decryption/session", &oversized)
        )
        .await
        .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    for (method, path) in [("POST", "/v1/decryption/unknown"), ("GET", "/v1/other")] {
        assert_eq!(
            call(&state, request(method, path, "{}")).await,
            (StatusCode::NOT_FOUND, "NotFound".to_owned()),
            "{method} {path}"
        );
    }
}
