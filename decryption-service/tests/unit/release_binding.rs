use super::*;

#[test]
fn replicas_under_the_same_quorum_key_derive_the_same_keys() {
    let owner = recipient_signer();
    let keys = service_keys(&service(), &owner);
    assert_eq!(service_keys(&service(), &owner), keys);
    assert_ne!(service_keys(&service_with_quorum_seed(2), &owner), keys);
}

#[test]
fn a_request_is_bound_to_the_quorum_key() {
    let service = service();
    let base = public_keys(&service, &recipient_signer());
    assert!(call(&service, &base).is_ok());

    let edits: [fn(&mut ServiceRequest); 3] = [
        |r| r.version = API_VERSION + 1,
        |r| r.quorum_key_id.push('x'),
        |r| r.quorum_key_epoch = 2,
    ];
    for edit in edits {
        let mut request = base.clone();
        edit(&mut request);
        refused(&service, &request);
    }

    let mut unknown = serde_json::to_value(envelope(&service, &base)).unwrap();
    unknown["unknown"] = serde_json::Value::Null;
    for body in [jcs_serialize(&unknown).unwrap(), "{}".to_owned()] {
        assert_eq!(
            execute(&service, body.as_bytes()).unwrap_err(),
            Failure::Invalid
        );
    }
}

#[tokio::test]
async fn the_router_advertises_the_operations_and_serves_them() {
    let service = std::sync::Arc::new(service());
    let app = router(service.clone());
    let response = app
        .clone()
        .oneshot(Request::get("/v1/info").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let info: ServiceInfo = parse_strict_json(&testing::body(response).await).unwrap();
    assert_eq!(
        info.supported_operations,
        [
            spr_tvc_wire::types::OperationKind::ServicePublicKeys,
            spr_tvc_wire::types::OperationKind::ServiceDecrypt
        ]
    );
    assert_eq!(info.proof_type, SERVICE_PROOF_TYPE);

    let request = public_keys(&service, &recipient_signer());
    let body = jcs_serialize(&envelope(&service, &request)).unwrap();
    let response = app
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
