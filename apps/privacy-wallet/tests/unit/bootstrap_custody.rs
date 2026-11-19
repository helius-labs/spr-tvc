use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::Mutex;
use turnkey_client::TurnkeyP256ApiKey;

fn params() -> SignRawPayloadIntentV2 {
    SignRawPayloadIntentV2 {
        sign_with: "wallet".into(),
        payload: "abcd".into(),
        encoding: PayloadEncoding::Hexadecimal,
        hash_function: HashFunction::NotApplicable,
    }
}

fn activity(status: &str) -> (StatusCode, Value) {
    (
        StatusCode::OK,
        json!({"activity": {
            "id": "request-1", "organizationId": "org", "status": status,
            "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", "fingerprint": "fingerprint",
            "intent": {"signRawPayloadIntentV2": params()},
            "result": {"signRawPayloadResult": {"r": "11", "s": "22", "v": ""}},
            "appProofs": [{"scheme": "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256", "publicKey": "public",
                "proofPayload": "proof", "signature": "signature"}]
        }}),
    )
}

type Requests = Arc<Mutex<Vec<(String, Value)>>>;

async fn server(
    responses: Vec<(StatusCode, Value)>,
) -> (
    TurnkeyClient<TurnkeyP256ApiKey>,
    tokio::task::JoinHandle<()>,
    Requests,
) {
    let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
    let requests: Requests = Arc::default();
    let captured = Arc::clone(&requests);
    let app = Router::new().fallback(move |request: Request<Body>| {
        let responses = Arc::clone(&responses);
        let captured = Arc::clone(&captured);
        async move {
            let path = request.uri().path().to_owned();
            let body = to_bytes(request.into_body(), 16_384).await.unwrap();
            captured
                .lock()
                .unwrap()
                .push((path, serde_json::from_slice(&body).unwrap()));
            let mut responses = responses.lock().unwrap();
            let response = if responses.len() > 1 {
                responses.pop_front().unwrap()
            } else {
                responses[0].clone()
            };
            (
                response.0,
                [("content-type", "application/json")],
                response.1.to_string(),
            )
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async { axum::serve(listener, app).await.unwrap() });
    let client = TurnkeyClient::builder()
        .api_key(TurnkeyP256ApiKey::generate())
        .base_url(url)
        .build()
        .unwrap();
    (client, task, requests)
}

#[tokio::test]
async fn approval_polls_the_original_activity() {
    for initial_status in [
        "ACTIVITY_STATUS_CONSENSUS_NEEDED",
        "ACTIVITY_STATUS_PENDING",
    ] {
        let (client, task, requests) = server(vec![
            activity(initial_status),
            activity("ACTIVITY_STATUS_PENDING"),
            activity("ACTIVITY_STATUS_COMPLETED"),
        ])
        .await;
        let result = sign_with_approval(&client, "org", 1000, params())
            .await
            .unwrap();
        task.abort();
        assert_eq!(result.activity_id, "request-1");
        assert_eq!(result.result.r, "11");
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].0, "/public/v1/submit/sign_raw_payload");
        for (path, body) in &requests[1..] {
            assert_eq!(path, "/public/v1/query/get_activity");
            assert_eq!(
                body,
                &json!({"organizationId": "org", "activityId": "request-1"})
            );
        }
    }
}

#[tokio::test]
async fn rejected_or_substituted_activities_cannot_complete_bootstrap() {
    for (field, value, declined) in [
        ("status", "ACTIVITY_STATUS_REJECTED", true),
        ("status", "ACTIVITY_STATUS_FAILED", true),
        ("id", "different-activity", false),
        ("organizationId", "different-org", false),
        ("type", "ACTIVITY_TYPE_SIGN_TRANSACTION_V2", false),
        ("payload", "different-message", false),
    ] {
        let (status, mut response) = activity("ACTIVITY_STATUS_COMPLETED");
        if field == "payload" {
            response["activity"]["intent"]["signRawPayloadIntentV2"][field] = json!(value);
        } else {
            response["activity"][field] = json!(value);
        }
        let (client, task, _) = server(vec![
            activity("ACTIVITY_STATUS_CONSENSUS_NEEDED"),
            (status, response),
        ])
        .await;
        let error = sign_with_approval(&client, "org", 1000, params())
            .await
            .unwrap_err();
        task.abort();
        assert_eq!(
            error,
            if declined {
                CustodyError::Declined
            } else {
                CustodyError::Unavailable
            }
        );
    }
}

#[tokio::test]
async fn a_new_grant_can_propagate_before_the_first_activity_is_created() {
    let (client, task, requests) = server(vec![
        (
            StatusCode::FORBIDDEN,
            json!({"code": 7, "message": "permission denied"}),
        ),
        activity("ACTIVITY_STATUS_CONSENSUS_NEEDED"),
        activity("ACTIVITY_STATUS_COMPLETED"),
    ])
    .await;
    let result = sign_with_approval(&client, "org", 1000, params())
        .await
        .unwrap();
    task.abort();
    assert_eq!(result.activity_id, "request-1");
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].0, requests[1].0);
    assert_ne!(requests[0].1["timestampMs"], requests[1].1["timestampMs"]);
    let mut retried = requests[0].1.clone();
    retried["timestampMs"] = requests[1].1["timestampMs"].clone();
    assert_eq!(retried, requests[1].1);
    assert_eq!(requests[2].0, "/public/v1/query/get_activity");
}

#[tokio::test]
async fn other_submission_errors_are_not_retried() {
    for status in [
        StatusCode::UNAUTHORIZED,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::BAD_GATEWAY,
        StatusCode::OK,
    ] {
        let (client, task, requests) = server(vec![
            (status, json!({"message": "failure"})),
            activity("ACTIVITY_STATUS_COMPLETED"),
        ])
        .await;
        assert_eq!(
            sign_with_approval(&client, "org", 1000, params())
                .await
                .unwrap_err(),
            CustodyError::Unavailable
        );
        task.abort();
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn permission_retries_are_bounded() {
    let (client, task, requests) = server(vec![(
        StatusCode::FORBIDDEN,
        json!({"code": 7, "message": "permission denied"}),
    )])
    .await;
    assert_eq!(
        sign_with_approval(&client, "org", 1000, params())
            .await
            .unwrap_err(),
        CustodyError::Unavailable
    );
    task.abort();
    assert_eq!(requests.lock().unwrap().len(), 11);
}

#[tokio::test]
async fn waiting_for_approval_can_be_cancelled_at_the_operation_deadline() {
    for initial_response in [
        activity("ACTIVITY_STATUS_CONSENSUS_NEEDED"),
        (StatusCode::FORBIDDEN, json!({"code": 7})),
    ] {
        let (client, task, requests) = server(vec![initial_response]).await;
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            sign_with_approval(&client, "org", 1000, params()),
        )
        .await;
        task.abort();
        assert!(result.is_err());
        assert_eq!(
            requests
                .lock()
                .unwrap()
                .iter()
                .filter(|(path, _)| path.ends_with("sign_raw_payload"))
                .count(),
            1
        );
    }
}
