use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use spr_tvc_enclave::testing::{self, body};
use spr_tvc_protocol::encoding::parse_strict_json;
use tower::ServiceExt as _;

use super::*;

fn app() -> Router {
    let quorum = P256Pair::generate().unwrap();
    let ephemeral = P256Pair::generate().unwrap();
    let info = testing::release().service_info(&APP, [0x22; 32], [0x33; 32], &quorum, &ephemeral);
    router(AppState::ready(Service::new(info, ephemeral, quorum)))
}

#[tokio::test]
async fn info_advertises_the_image_network_and_the_wallet_operations() {
    let response = app()
        .oneshot(Request::get("/v1/info").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let info: ServiceInfo = parse_strict_json(&body(response).await).unwrap();
    assert_eq!(info.network, spr_tvc_enclave::NETWORK);
    assert_eq!(info.supported_operations, OPERATIONS);
    assert_eq!(info.proof_type, TVC_APP_PROOF_TYPE);
}

#[tokio::test]
async fn operations_reach_the_wallet_handler() {
    let response = app()
        .oneshot(
            Request::post("/v1/operations")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body(response).await, r#"{"error":"InvalidRequest"}"#);
}
