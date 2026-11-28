//! Shared QOS envelope vector interoperability against Turnkey's qos_p256 crate (INV-12).

use qos_p256::encrypt::P256EncryptPair;
use serde_json::Value;
use sha2::{Digest, Sha256};
use spr_tvc_wire::encoding::decode_lower_hex;
use zeroize::Zeroizing;

fn bytes(value: &Value) -> Vec<u8> {
    decode_lower_hex(value.as_str().unwrap()).unwrap()
}

#[test]
fn qos_crate_authenticates_the_shared_envelope() {
    let positive: Value =
        serde_json::from_str(include_str!("../fixtures/qos-borsh-envelope.json")).unwrap();
    let negative: Value =
        serde_json::from_str(include_str!("../fixtures/qos-negative.json")).unwrap();
    let envelope = bytes(&positive["envelope"]);
    let secret = Zeroizing::new(Sha256::digest(b"spr-tvc-test-encryption-sk").to_vec());
    let receiver = P256EncryptPair::from_bytes(&secret).unwrap();
    let wrong_receiver =
        P256EncryptPair::from_bytes(&Zeroizing::new(bytes(&negative["wrong_receiver_secret"])))
            .unwrap();

    assert_eq!(
        receiver.decrypt(&envelope).unwrap().as_slice(),
        bytes(&positive["plaintext"])
    );
    assert!(wrong_receiver.decrypt(&envelope).is_err());
    assert!(receiver
        .decrypt(&bytes(&negative["truncated_envelope"]))
        .is_err());
}
