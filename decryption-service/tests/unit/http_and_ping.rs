//! Enclave HTTP surface (/health, /v1/info, /v1/ping) and body ceiling tests (INV-07, INV-08).

use axum::http::StatusCode;
use spr_tvc_wire::constants::{QOS_P256_PUBLIC_LEN, RAW_P256_SIGNATURE_LEN};
use spr_tvc_wire::crypto::verify_p256_message;
use spr_tvc_wire::encoding::{jcs_serialize, parse_strict_json};
use spr_tvc_wire::types::{QosPingChallenge, QosPingRequest};
use tower::ServiceExt as _;

use std::sync::Arc;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::Request;
use axum::Router;
use qos_p256::P256Pair;
use spr_tvc_wire::constants::{
    API_VERSION, MAX_ENCRYPTED_REQUEST_BYTES, TVC_APP_PROOF_SCHEME, TVC_QOS_PING_PROOF_TYPE,
};
use spr_tvc_wire::types::{QosPingResponse, ServiceInfo};

use crate::release::NETWORK;
use crate::service::{router, Service};
use crate::tests::testing;

fn info(quorum: &P256Pair) -> ServiceInfo {
    testing::release().service_info([0x22; 32], [0x33; 32], quorum)
}

fn app(quorum: P256Pair, ephemeral: P256Pair) -> Router {
    router(Arc::new(Service::new(info(&quorum), ephemeral, quorum)))
}

#[tokio::test]
async fn health_is_exact() {
    let quorum = P256Pair::generate().unwrap();
    let ephemeral = P256Pair::generate().unwrap();
    let response = app(quorum, ephemeral)
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
    assert_eq!(testing::body(response).await, r#"{"status":"Healthy"}"#);
}

#[tokio::test]
async fn info_is_untrusted_discovery_bound_to_runtime_public_keys() {
    let quorum = P256Pair::generate().unwrap();
    let ephemeral = P256Pair::generate().unwrap();
    let expected = info(&quorum);
    let response = app(quorum, ephemeral)
        .oneshot(Request::get("/v1/info").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let actual: ServiceInfo = parse_strict_json(&testing::body(response).await).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(actual.network, NETWORK);
}

#[tokio::test]
async fn ping_decrypts_with_quorum_and_signs_exact_utf8_with_ephemeral() {
    let quorum = P256Pair::generate().unwrap();
    let ephemeral = P256Pair::generate().unwrap();
    let quorum_public = quorum.public_key();
    let ephemeral_public = ephemeral.public_key();
    let proof_payload = jcs_serialize(&QosPingChallenge {
        r#type: TVC_QOS_PING_PROOF_TYPE.to_owned(),
        version: API_VERSION,
        challenge: [0x44; 32],
    })
    .unwrap();
    let encrypted_challenge = quorum_public.encrypt(proof_payload.as_bytes()).unwrap();
    let request_body = jcs_serialize(&QosPingRequest {
        version: API_VERSION,
        encrypted_challenge,
    })
    .unwrap();
    let response = app(quorum, ephemeral)
        .oneshot(
            Request::post("/v1/ping")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(request_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let response: QosPingResponse = parse_strict_json(&testing::body(response).await).unwrap();
    let proof = response.tvc_app_proof;
    assert_eq!(proof.scheme, TVC_APP_PROOF_SCHEME);
    assert_eq!(proof.public_key, ephemeral_public.to_bytes());
    assert_eq!(proof.public_key.len(), QOS_P256_PUBLIC_LEN);
    assert_eq!(proof.proof_payload.as_bytes(), proof_payload.as_bytes());
    assert_eq!(proof.signature.len(), RAW_P256_SIGNATURE_LEN);
    ephemeral_public
        .verify(proof.proof_payload.as_bytes(), &proof.signature)
        .unwrap();
    assert!(quorum_public
        .verify(proof.proof_payload.as_bytes(), &proof.signature)
        .is_err());
    verify_p256_message(
        &ephemeral_public.signing_public_key_bytes(),
        proof.proof_payload.as_bytes(),
        &proof.signature,
    )
    .unwrap();
}

#[tokio::test]
async fn ping_rejects_ephemeral_encryption_and_noncanonical_plaintext_generically() {
    let quorum = P256Pair::generate().unwrap();
    let ephemeral = P256Pair::generate().unwrap();
    let noncanonical = format!(
        r#"{{"version":1,"type":"{TVC_QOS_PING_PROOF_TYPE}","challenge":"{}"}}"#,
        "55".repeat(32)
    );
    let cases = [
        ephemeral
            .public_key()
            .encrypt(b"not for the quorum")
            .unwrap(),
        quorum
            .public_key()
            .encrypt(noncanonical.as_bytes())
            .unwrap(),
    ];
    let app = app(quorum, ephemeral);

    for encrypted_challenge in cases {
        let body = jcs_serialize(&QosPingRequest {
            version: API_VERSION,
            encrypted_challenge,
        })
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/ping")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            testing::body(response).await,
            r#"{"error":"InvalidRequest"}"#
        );
    }
}

#[tokio::test]
async fn ping_rejects_wrong_method_and_oversized_body() {
    let quorum = P256Pair::generate().unwrap();
    let ephemeral = P256Pair::generate().unwrap();
    let app = app(quorum, ephemeral);

    let response = app
        .clone()
        .oneshot(Request::get("/v1/ping").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    let response = app
        .oneshot(
            Request::post("/v1/ping")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(vec![
                    0u8;
                    MAX_ENCRYPTED_REQUEST_BYTES as usize + 1
                ]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn every_other_request_gets_a_generic_json_error() {
    let quorum = P256Pair::generate().unwrap();
    let ephemeral = P256Pair::generate().unwrap();
    let app = app(quorum, ephemeral);
    let request = |method: &str, path: &str, content_type: &str, body: Vec<u8>| {
        let mut request = Request::builder().method(method).uri(path);
        if !content_type.is_empty() {
            request = request.header(CONTENT_TYPE, content_type);
        }
        request.body(Body::from(body)).unwrap()
    };
    let json = "application/json";
    let oversized = vec![0u8; MAX_ENCRYPTED_REQUEST_BYTES as usize + 1];
    let not_allowed = (StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed");
    let not_found = (StatusCode::NOT_FOUND, "NotFound");
    let invalid = (StatusCode::BAD_REQUEST, "InvalidRequest");
    let cases = [
        (
            request("GET", "/v1/operations", "", Vec::new()),
            not_allowed,
        ),
        (request("PUT", "/v1/ping", json, Vec::new()), not_allowed),
        (request("POST", "/health", json, Vec::new()), not_allowed),
        (request("DELETE", "/v1/info", "", Vec::new()), not_allowed),
        (request("GET", "/v1/unknown", "", Vec::new()), not_found),
        (request("POST", "/", json, Vec::new()), not_found),
        (
            request("POST", "/v1/operations", "text/plain", Vec::new()),
            invalid,
        ),
        (request("POST", "/v1/ping", "", Vec::new()), invalid),
        (
            request(
                "POST",
                "/v1/operations",
                "application/json; charset=utf-8",
                b"{}".to_vec(),
            ),
            invalid,
        ),
        (
            request("GET", "/health", "", b"x".to_vec()),
            (StatusCode::PAYLOAD_TOO_LARGE, "RequestTooLarge"),
        ),
        (
            request("GET", "/v1/info", "", b"x".to_vec()),
            (StatusCode::PAYLOAD_TOO_LARGE, "RequestTooLarge"),
        ),
        (
            request("GET", "/health", "", oversized),
            (StatusCode::PAYLOAD_TOO_LARGE, "RequestTooLarge"),
        ),
    ];
    for (request, (status, error)) in cases {
        let target = format!("{} {}", request.method(), request.uri());
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), status, "{target}");
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        assert_eq!(
            testing::body(response).await,
            format!(r#"{{"error":"{error}"}}"#),
            "{target}"
        );
    }
}
