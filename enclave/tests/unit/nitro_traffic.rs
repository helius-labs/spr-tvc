use axum::body::Body;
use tower::ServiceExt;

use super::*;

#[tokio::test]
async fn wallet_preflight_allows_only_credential_free_json_and_attestation_posts() {
    let transport = NativePair::generate().unwrap();
    let service = Arc::new(Service {
        info: Release {
            security_domain_id: [1; 32],
            release_id: "fixture".into(),
            quorum_key_id: "fixture".into(),
            quorum_key_epoch: 1,
        }
        .service_info([2; 32], [3; 32], transport.public.clone()),
        quorum: KeyPair::Native(transport),
        ephemeral: KeyPair::Native(NativePair::generate().unwrap()),
        note_seed: NoteSeed(Zeroizing::new([4; 32])),
    });
    let router = serving_router(service);
    for path in ["/v1/nitro/attestation", "/v1/operations"] {
        let request = Request::builder()
            .method(Method::OPTIONS)
            .uri(path)
            .header(header::ORIGIN, "https://wallet.example")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert!(response.status().is_success());
        assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert_eq!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_METHODS],
            "POST"
        );
        assert_eq!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS],
            "content-type"
        );
        assert!(response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none());
    }

    let request = Request::post("/v1/nitro/attestation")
        .header(header::ORIGIN, "https://wallet.example")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
}

#[tokio::test]
async fn cancelled_attestation_cannot_admit_another_kernel_call() {
    let worker = Arc::new(Semaphore::new(1));
    let (started, wait_for_worker) = oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let request = tokio::spawn(issue_attestation(worker.clone(), move || {
        started.send(()).unwrap();
        blocked.recv_timeout(Duration::from_secs(2)).unwrap();
        Ok(([(CONTENT_TYPE, "application/json")], String::new()))
    }));
    wait_for_worker.await.unwrap();
    request.abort();
    assert_eq!(
        issue_attestation::<String>(worker.clone(), || panic!("worker was full"))
            .await
            .unwrap_err(),
        StatusCode::TOO_MANY_REQUESTS
    );
    release.send(()).unwrap();
    let permit = tokio::time::timeout(Duration::from_secs(1), worker.acquire())
        .await
        .unwrap()
        .unwrap();
    drop(permit);
}

#[tokio::test]
async fn request_budget_fails_fast_and_releases_capacity_at_deadline() {
    let capacity = Arc::new(Semaphore::new(1));
    let started = Arc::new(tokio::sync::Notify::new());
    let handler_started = started.clone();
    let service = Router::new()
        .route(
            "/",
            get(move || async move {
                handler_started.notify_one();
                std::future::pending::<StatusCode>().await
            }),
        )
        .layer(middleware::from_fn_with_state(
            capacity.clone(),
            limit_serving_request,
        ));

    let first = tokio::spawn(service.clone().oneshot(Request::new(Body::empty())));
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .unwrap();
    let rejected = service.oneshot(Request::new(Body::empty())).await.unwrap();
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    let expired = tokio::time::timeout(SERVING_DEADLINE + Duration::from_secs(1), first)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(expired.status(), StatusCode::REQUEST_TIMEOUT);
    assert_eq!(capacity.available_permits(), 1);
}
