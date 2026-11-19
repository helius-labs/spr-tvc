use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecodedStamp {
    public_key: String,
    signature: String,
    scheme: String,
}

#[test]
fn stamps_with_the_qos_signing_subkey() {
    let pair = Arc::new(P256Pair::generate().unwrap());
    let expected = pair
        .public_key()
        .signing_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let stamper = QosTurnkeyStamper::new(pair);
    let body = br#"{"hello":"turnkey"}"#;
    let header = stamper.stamp(body).unwrap();
    assert_eq!(header.name, API_KEY_STAMP_HEADER_NAME);
    let decoded: DecodedStamp =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header.value).unwrap()).unwrap();
    assert_eq!(decoded.scheme, SIGNATURE_SCHEME_P256);
    assert_eq!(hex::decode(&decoded.public_key).unwrap(), expected);
    let verifying_key = VerifyingKey::from_sec1_bytes(&expected).unwrap();
    let signature = Signature::from_der(&hex::decode(decoded.signature).unwrap()).unwrap();
    verifying_key.verify(body, &signature).unwrap();
}
