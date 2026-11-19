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
        decryption_enclave: None,
        turnkey: Turnkey::for_tests(UNREACHABLE),
        provisioner: crate::provisioner::tests::provisioner(),
        enrollment: crate::enrollment::tests::enrollment(&[crate::enrollment::tests::DOMAIN]),
        wallet_grants: crate::wallet_grant::tests::grants(Vec::new()),
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

fn descriptor(state: &AppState) -> WalletDescriptor {
    state
        .provisioner
        .sign(&crate::enrollment::tests::input())
        .expect("descriptor did not sign")
}

fn operation(descriptor: &WalletDescriptor, ciphertext: &str) -> String {
    serde_json::json!({
        "descriptor": descriptor,
        "request": {
            "version": spr_tvc_protocol::constants::API_VERSION,
            "quorum_key_id": "q",
            "quorum_key_epoch": "1",
            "ciphertext": ciphertext,
        },
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
    let mut forged = request("POST", "/v1/private-wallet/session", "{}");
    forged.headers_mut().insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer forged"),
    );
    assert_eq!(
        call(&state, forged).await,
        (StatusCode::UNAUTHORIZED, "OriginAuthRequired".to_owned())
    );
    let mut anonymous = request("POST", "/v1/private-wallet/session", "{}");
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
        call(&state, direct("/v1/private-wallet/session")).await,
        (StatusCode::UNAUTHORIZED, "ApiKeyRequired".to_owned())
    );
    assert_eq!(
        call(
            &state,
            direct("/v1/private-wallet/session?api-key=not%20a%20key")
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
            direct(&format!("/v1/private-wallet/session?api-key={key}"))
        )
        .await,
        unresolved
    );
    let mut by_header = direct("/v1/private-wallet/session");
    by_header.headers_mut().insert(
        crate::project::API_KEY_HEADER,
        HeaderValue::from_static(key),
    );
    assert_eq!(call(&state, by_header).await, unresolved);
}

#[tokio::test]
async fn an_operation_needs_a_descriptor_this_gateway_provisioned() {
    let state = state();
    let operations = |body: String| {
        call(
            &state,
            request("POST", "/v1/private-wallet/operations", &body),
        )
    };
    assert_eq!(
        operations(r#"{"request":{}}"#.to_owned()).await,
        (StatusCode::BAD_REQUEST, "InvalidJson".to_owned())
    );
    let mut tampered = descriptor(&state);
    tampered.turnkey_wallet_id = "3b2c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e".to_owned();
    assert_eq!(
        operations(operation(&tampered, "abcd")).await,
        (StatusCode::FORBIDDEN, "InvalidDescriptor".to_owned())
    );
    // Enrolled two days ago, for a day.
    let two_days_ago = provisioner::now_ms().expect("clock") - 2 * 86_400_000;
    let expired = state
        .provisioner
        .sign(&crate::enrollment::EnrollmentInput {
            issued_at_ms: two_days_ago,
            ..crate::enrollment::tests::input()
        })
        .expect("descriptor did not sign");
    assert_eq!(
        operations(operation(&expired, "abcd")).await,
        (StatusCode::FORBIDDEN, "DescriptorExpired".to_owned())
    );
}

#[tokio::test]
async fn a_ciphertext_that_never_reached_the_enclave_can_be_resent() {
    let state = state();
    let descriptor = descriptor(&state);
    let operations = |body: String| {
        call(
            &state,
            request("POST", "/v1/private-wallet/operations", &body),
        )
    };
    let unreachable_turnkey = (
        StatusCode::FAILED_DEPENDENCY,
        "TurnkeyUnavailable".to_owned(),
    );
    assert_eq!(
        operations(operation(&descriptor, "abcd")).await,
        unreachable_turnkey
    );
    assert_eq!(
        operations(operation(&descriptor, "abcd")).await,
        unreachable_turnkey
    );
}

fn enrollment_body(request: &EnrollmentRequest) -> String {
    serde_json::json!({
        "organizationId": request.organization_id,
        "turnkeyWalletId": request.turnkey_wallet_id,
        "solanaAddress": request.solana_address,
        "clientPublicKey": request.client_public_key,
        "issuedAtMs": request.issued_at_ms,
        "ownerSignature": request.owner_signature,
    })
    .to_string()
}

#[tokio::test]
async fn an_enrollment_takes_one_of_the_projects_in_flight_slots() {
    let state = state();
    let now = provisioner::now_ms().expect("clock");
    let body = enrollment_body(&crate::enrollment::tests::signed_request(now));
    let held: Vec<_> = (0..4)
        .map(|_| {
            state
                .limiter
                .try_acquire(&ProjectId::for_tests(PROJECT))
                .expect("a free slot")
        })
        .collect();
    assert_eq!(
        call(&state, request("POST", "/v1/private-wallet/enroll", &body)).await,
        (StatusCode::TOO_MANY_REQUESTS, "TooManyInFlight".to_owned())
    );
    drop(held);
    assert_eq!(
        call(&state, request("POST", "/v1/private-wallet/enroll", &body)).await,
        (
            StatusCode::FAILED_DEPENDENCY,
            "TurnkeyUnavailable".to_owned()
        )
    );
}

#[tokio::test]
async fn a_stale_or_malformed_enrollment_is_refused_before_turnkey_is_asked() {
    let state = state();
    let future = crate::enrollment::tests::signed_request(crate::enrollment::tests::NOW);
    let body = enrollment_body(&future);
    assert_eq!(
        call(&state, request("POST", "/v1/private-wallet/enroll", &body)).await,
        (StatusCode::BAD_REQUEST, "StaleEnrollment".to_owned())
    );
    assert_eq!(
        call(&state, request("POST", "/v1/private-wallet/enroll", "{}")).await,
        (StatusCode::BAD_REQUEST, "InvalidJson".to_owned())
    );
}

#[tokio::test]
async fn oversized_enclave_bodies_and_other_routes_are_refused() {
    let state = state();
    let oversized = "x".repeat(8_192);
    assert_eq!(
        call(
            &state,
            request("POST", "/v1/private-wallet/session", &oversized)
        )
        .await
        .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    for (method, path) in [("POST", "/v1/private-wallet/unknown"), ("GET", "/v1/other")] {
        assert_eq!(
            call(&state, request(method, path, "{}")).await,
            (StatusCode::NOT_FOUND, "NotFound".to_owned()),
            "{method} {path}"
        );
    }
}
