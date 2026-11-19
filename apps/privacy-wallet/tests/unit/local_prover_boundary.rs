use super::*;
use tower::ServiceExt;

#[tokio::test]
async fn attestation_preserves_its_contract_under_a_gateway_prefix() {
    for prefix in ["", "/v1/proxy"] {
        let prover = LocalProver::new("http://127.0.0.1:1");
        let expected_key = hex::encode(prover.prover.hpke_public_key());
        let request = axum::http::Request::builder()
            .uri(format!(
                "{prefix}{ATTESTATION_PATH}?nonce={}",
                "00".repeat(32)
            ))
            .body(Body::empty())
            .unwrap();
        let response = prover.router().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let attestation: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(attestation["hpke_public_key"], expected_key);
        assert_eq!(attestation["platform"], "aws-nitro");
    }
}
