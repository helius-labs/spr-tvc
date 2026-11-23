use axum::body::Body;
use ed25519_dalek::SigningKey;
use solana_pubkey::Pubkey;
use spr_keypair::NullifierKey;
use spr_tvc_protocol::{
    decryption_service::{service_request_digest, ServiceOperation, ServiceRequest, ServiceResult},
    encoding::{jcs_serialize, parse_strict_json},
    types::EncryptedResponse,
};
use tower::ServiceExt;

use super::*;
use crate::testing;

fn service() -> Arc<Service> {
    let transport = NativePair::generate().unwrap();
    Arc::new(Service {
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
        now_ms: || Some(1_795_290_720_000),
    })
}

fn app(service: Arc<Service>, operations: Arc<OperationTraffic>) -> Router {
    serving_router(
        service,
        BootstrapEvidence {
            slots: [1, 3, 5],
            booted_at_ms: 1_795_290_719_965,
        },
        operations,
    )
}

#[tokio::test]
async fn native_route_seals_owner_authorized_notes_to_the_signed_response_key() {
    let service = service();
    let router = app(service.clone(), Arc::new(OperationTraffic::new()));
    let owner = SigningKey::from_bytes(&[5; 32]);
    let address = Pubkey::new_from_array(owner.verifying_key().to_bytes()).to_string();
    let response_secret = [0x42; 32];
    let other_secret = [0x43; 32];
    let send = async |request: &ServiceRequest| {
        let encrypted = testing::encrypt_request(&service.info, &jcs_serialize(request).unwrap());
        let http = Request::post("/v1/operations")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(jcs_serialize(&encrypted).unwrap()))
            .unwrap();
        router.clone().oneshot(http).await.unwrap()
    };
    let lookup = testing::request(
        &service.info,
        ServiceOperation::PublicKeys {
            address: address.clone(),
        },
        &response_secret,
    );
    let reply = send(&lookup).await;
    assert_eq!(reply.status(), StatusCode::OK);
    let proof_key = service.ephemeral.public_bytes();
    let (_, plaintext) =
        testing::open_response(&proof_key, &testing::body(reply).await, &response_secret);
    let ServiceResult::PublicKeys {
        viewing_public_key,
        nullifier_public_key,
    } = parse_strict_json(std::str::from_utf8(&plaintext).unwrap()).unwrap()
    else {
        panic!("expected a PublicKeys result");
    };

    let note = b"native transfer note";
    let mut decrypt = testing::request(
        &service.info,
        ServiceOperation::Decrypt {
            signer: address,
            expires_at_ms: 1_795_290_721_000,
            signature: [0; 64],
            items: vec![testing::transfer_output(viewing_public_key, note, 3)],
        },
        &response_secret,
    );
    decrypt.request_id[0] ^= 1;
    testing::sign_decrypt(&mut decrypt, &SigningKey::from_bytes(&[9; 32]), NETWORK);
    assert_eq!(send(&decrypt).await.status(), StatusCode::BAD_REQUEST);

    testing::sign_decrypt(&mut decrypt, &owner, NETWORK);
    let reply = send(&decrypt).await;
    assert_eq!(reply.status(), StatusCode::OK);
    let body = testing::body(reply).await;
    let envelope: EncryptedResponse = parse_strict_json(&body).unwrap();
    assert!(testing::response_key(&other_secret)
        .decrypt(&envelope.encrypted_result)
        .is_err());
    let (proof, plaintext) = testing::open_response(&proof_key, &body, &response_secret);
    assert_eq!(
        proof.request_digest,
        service_request_digest(&decrypt).unwrap()
    );
    assert_eq!(proof.request_id, decrypt.request_id);
    assert_eq!(proof.operation, decrypt.operation.kind());
    let ServiceResult::Decrypt(result) =
        parse_strict_json(std::str::from_utf8(&plaintext).unwrap()).unwrap()
    else {
        panic!("expected a Decrypt result");
    };
    assert_eq!(result.plaintexts, [note.to_vec()]);
    assert_eq!(
        NullifierKey::from_secret(result.nullifier_secret)
            .pubkey()
            .unwrap(),
        nullifier_public_key
    );

    decrypt.client_response_public_key = testing::response_point(&other_secret);
    assert_eq!(send(&decrypt).await.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn wallet_preflight_allows_only_credential_free_json_and_attestation_posts() {
    let router = app(service(), Arc::new(OperationTraffic::new()));
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
async fn operation_overload_leaves_health_available_without_reading_request_bodies() {
    struct Unreadable;
    impl axum::body::HttpBody for Unreadable {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
            panic!("the dispatcher polled the body");
        }
    }

    let operations = Arc::new(OperationTraffic::new());
    let router = app(service(), operations.clone());
    let _load = operations
        .requests
        .try_acquire_many(MAX_SERVING_REQUESTS.try_into().unwrap())
        .unwrap();
    for (method, path, content_type, expected) in [
        (Method::GET, "/health", "", StatusCode::OK),
        (Method::GET, "/v1/info", "", StatusCode::NOT_FOUND),
        (Method::GET, "/v1/unknown", "", StatusCode::NOT_FOUND),
        (
            Method::POST,
            "/v1/ping",
            "application/json",
            StatusCode::NOT_FOUND,
        ),
        (
            Method::POST,
            "/v1/operations",
            "text/plain",
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::POST,
            "/v1/operations",
            "application/json",
            StatusCode::TOO_MANY_REQUESTS,
        ),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::new(Unreadable))
            .unwrap();
        assert_eq!(
            router.clone().oneshot(request).await.unwrap().status(),
            expected
        );
    }
}

#[tokio::test]
async fn crypto_waits_for_capacity_without_blocking_health() {
    let service = State(service());
    let operations = Extension(Arc::new(OperationTraffic::new()));
    let permit = operations.0.worker.try_acquire().unwrap();
    let request = Request::post("/v1/operations")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let response = serve_request(service.clone(), operations.clone(), request);
    tokio::pin!(response);
    tokio::select! {
        biased;
        result = &mut response => panic!("crypto ran with no capacity: {}", result.status()),
        _ = std::future::ready(()) => {}
    }
    let request = Request::get("/health").body(Body::empty()).unwrap();
    let health = tokio::time::timeout(
        SERVING_DEADLINE,
        serve_request(service.clone(), operations.clone(), request),
    )
    .await
    .unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    drop(permit);
    let response = tokio::time::timeout(SERVING_DEADLINE, response)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn cancelled_request_cannot_admit_another_blocking_operation() {
    let worker = Arc::new(Semaphore::new(1));
    let (started, wait_for_worker) = oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let request = tokio::spawn(with_worker(worker.clone(), move || {
        started.send(()).unwrap();
        blocked.recv_timeout(Duration::from_secs(2)).unwrap();
        Ok(())
    }));
    wait_for_worker.await.unwrap();
    request.abort();
    assert_eq!(
        with_worker::<()>(worker.clone(), || panic!("worker was full"))
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

#[tokio::test(start_paused = true)]
async fn custody_worker_refuses_work_and_replies_past_the_listener_deadline() {
    let worker = Arc::new(Semaphore::new(1));
    let deadline = Instant::now() + Duration::from_secs(1);
    let (started, wait_for_worker) = oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let request = tokio::spawn(with_worker_before(worker.clone(), deadline, move || {
        started.send(()).unwrap();
        blocked.recv_timeout(Duration::from_secs(2)).unwrap();
        Ok("late reply")
    }));
    wait_for_worker.await.unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    release.send(()).unwrap();
    assert_eq!(request.await.unwrap(), Err(StatusCode::GONE));
    assert_eq!(
        with_worker_before::<()>(worker, deadline, || panic!("expired worker ran")).await,
        Err(StatusCode::GONE),
    );
}

#[tokio::test(start_paused = true)]
async fn request_budget_fails_fast_and_releases_capacity_at_deadline() {
    let capacity = Arc::new(Semaphore::new(1));
    let started = Arc::new(tokio::sync::Notify::new());
    let handler_started = started.clone();
    let service = Router::new()
        .route(
            "/",
            get(move || async move {
                handler_started.notify_one();
                tokio::time::sleep(SERVING_DEADLINE).await;
                StatusCode::OK
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
