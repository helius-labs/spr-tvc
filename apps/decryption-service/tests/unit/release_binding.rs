use super::*;

#[test]
fn the_service_keys_follow_the_quorum_key_and_nothing_else() {
    let owner = SigningKey::from_bytes(&[5; 32]);
    let keys = service_keys(&service(), &owner);
    // Another release or replica under the same Quorum key.
    assert_eq!(service_keys(&service_on(NETWORK, 1), &owner), keys);
    assert_ne!(service_keys(&service_on(NETWORK, 2), &owner), keys);
}

#[test]
fn a_request_is_bound_to_the_running_release() {
    let service = service();
    let base = public_keys(&service, &SigningKey::from_bytes(&[5; 32]));
    assert!(call(&service, &base).is_ok());

    let edits: [fn(&mut ServiceRequest); 7] = [
        |r| r.version = 2,
        |r| r.target_release_id.push('x'),
        |r| r.target_manifest_digest[0] ^= 1,
        |r| r.target_executable_digest[0] ^= 1,
        |r| r.quorum_key_id.push('x'),
        |r| r.quorum_key_epoch = 2,
        |r| r.client_response_public_key = vec![0; 65],
    ];
    for edit in edits {
        let mut request = base.clone();
        edit(&mut request);
        refused(&service, &request);
    }

    let mut with_grant = envelope(&service, &base);
    with_grant.wallet_grant = Some(WalletGrant {
        version: API_VERSION,
        descriptor_digest: [0; 32],
        client_key_id: String::new(),
        project_id: String::new(),
        issued_at_ms: 0,
        expires_at_ms: 0,
        signature: Vec::new(),
    });
    for body in [jcs_serialize(&with_grant).unwrap(), "{}".to_owned()] {
        assert_eq!(
            execute(&service, body.as_bytes()).unwrap_err(),
            Failure::Invalid
        );
    }
}

#[tokio::test]
async fn the_router_advertises_the_operations_and_serves_them() {
    let service = service();
    let response = router(service.clone())
        .oneshot(Request::get("/v1/info").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let info: ServiceInfo = parse_strict_json(&testing::body(response).await).unwrap();
    assert_eq!(info.supported_operations, OPERATIONS);
    assert_eq!(info.proof_type, SERVICE_PROOF_TYPE);

    let request = public_keys(&service, &SigningKey::from_bytes(&[5; 32]));
    let body = jcs_serialize(&envelope(&service, &request)).unwrap();
    let response = router(service.clone())
        .oneshot(
            Request::post("/v1/operations")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result = open(&service, &request, &testing::body(response).await);
    assert!(matches!(result, ServiceResult::PublicKeys { .. }));
}
