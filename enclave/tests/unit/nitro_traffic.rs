use axum::body::Body;
use tower::ServiceExt;

use super::*;

#[tokio::test]
async fn cancelled_attestation_cannot_admit_another_kernel_call() {
    let worker = Arc::new(Semaphore::new(1));
    let (started, wait_for_worker) = oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let request = tokio::spawn(issue_serving_attestation(worker.clone(), move || {
        started.send(()).unwrap();
        blocked.recv_timeout(Duration::from_secs(2)).unwrap();
        Ok(([(CONTENT_TYPE, "application/json")], String::new()))
    }));
    wait_for_worker.await.unwrap();
    request.abort();
    assert_eq!(
        issue_serving_attestation(worker.clone(), || panic!("worker was full"))
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
