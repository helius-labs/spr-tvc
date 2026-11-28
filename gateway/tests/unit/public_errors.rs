//! Gateway RFC 7807 problem-document and non-retriable error code tests (INV-27).

use super::*;

#[test]
fn the_code_is_the_variant_name_and_no_failure_is_retried_by_gatekeeper() {
    assert_eq!(ApiError::InvalidJson.code(), "InvalidJson");
    assert_eq!("InvalidJson".parse(), Ok(ApiError::InvalidJson));
    for error in [ApiError::EnclaveUnavailable, ApiError::TurnkeyUnavailable] {
        assert_eq!(error.status(), StatusCode::FAILED_DEPENDENCY);
    }
}

#[tokio::test]
async fn a_failure_is_a_problem_document() {
    let response = ApiError::TooManyInFlight.into_response();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE),
        Some(&PROBLEM_JSON)
    );
    assert_eq!(
        response.headers().get(header::RETRY_AFTER),
        Some(&RETRY_AFTER_SECS)
    );
    let body = axum::body::to_bytes(response.into_body(), 4_096)
        .await
        .expect("body reads");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).expect("body is JSON"),
        serde_json::json!({
            "title": "Too Many Requests",
            "status": 429,
            "detail": "too many requests in flight",
            "code": "TooManyInFlight",
        })
    );
}
