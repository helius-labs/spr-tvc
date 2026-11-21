use super::*;

#[test]
fn replicas_under_the_same_quorum_key_derive_the_same_keys() {
    let owner = recipient_signer();
    let keys = service_keys(&service(), &owner);
    assert_eq!(service_keys(&service(), &owner), keys);
    assert_ne!(service_keys(&service_with_quorum_seed(2), &owner), keys);
}

#[test]
fn restored_note_seed_opens_a_note_under_a_new_quorum_key_and_release() {
    let owner = recipient_signer();
    let source = service();
    let keys = service_keys(&source, &owner);
    let plaintext = b"note received at the source";
    let item = transfer_output(keys.0, plaintext, 0);
    let source_request = decrypt(&source, &owner, NETWORK, vec![item.clone()]);
    let source_envelope = jcs_serialize(&envelope(&source, &source_request)).unwrap();
    let source_result = decrypted(&source, &source_request);
    assert_eq!(source_result.plaintexts, [plaintext.to_vec()]);

    let mut destination = service_with_quorum_seed(2);
    destination.info.release_id = "restored-release".into();
    destination.info.manifest_digest = [0x44; 32];
    destination.info.quorum_key_id = "restored-quorum".into();
    destination.info.quorum_key_epoch = 2;
    assert_ne!(service_keys(&destination, &owner), keys);
    destination.note_seed = source.note_seed;
    assert_eq!(service_keys(&destination, &owner), keys);
    assert!(execute(&destination, source_envelope.as_bytes()).is_err());
    refused(&destination, &source_request);

    let new_request = decrypt(&destination, &owner, NETWORK, vec![item]);
    let mut stale_approval = new_request.clone();
    let (
        ServiceOperation::Decrypt { signature, .. },
        ServiceOperation::Decrypt {
            signature: source_signature,
            ..
        },
    ) = (&mut stale_approval.operation, &source_request.operation)
    else {
        unreachable!();
    };
    *signature = *source_signature;
    refused(&destination, &stale_approval);
    let result = decrypted(&destination, &new_request);
    assert_eq!(result.plaintexts, [plaintext.to_vec()]);
    assert_eq!(result.nullifier_secret, source_result.nullifier_secret);
}

#[test]
fn a_request_is_bound_to_the_running_release() {
    let service = service();
    let base = public_keys(&service, &recipient_signer());
    assert!(call(&service, &base).is_ok());

    let edits: [fn(&mut ServiceRequest); 6] = [
        |r| r.version = API_VERSION + 1,
        |r| r.target_release_id.push('x'),
        |r| r.target_manifest_digest[0] ^= 1,
        |r| r.target_executable_digest[0] ^= 1,
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
            spr_tvc_protocol::types::OperationKind::ServicePublicKeys,
            spr_tvc_protocol::types::OperationKind::ServiceDecrypt
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
