use openssl::{pkey::PKey, rsa::Rsa};
use p256::ecdsa::SigningKey;
use serde_json::{json, Value};
use spr_tvc_protocol::encoding::encode_lower_hex;

use super::*;

fn configuration(deployment: Value) -> Value {
    json!({
        "securityDomainId": "12".repeat(32),
        "releaseId": "release-1",
        "deployment": deployment,
    })
}

fn custody() -> Value {
    json!({
        "epoch": "1",
        "noteSeedCommitment": "34".repeat(32),
        "shareCommitments": (1..=6).map(|index| format!("{index:02x}").repeat(32)).collect::<Vec<_>>(),
    })
}

#[test]
fn validates_the_serving_configuration() {
    let mut config = configuration(json!({"mode": "serve", "custody": custody()}));
    assert!(parse_configuration(&config.to_string()).is_ok());
    config["deployment"]["custody"]["shareCommitments"][1] =
        config["deployment"]["custody"]["shareCommitments"][0].clone();
    assert!(parse_configuration(&config.to_string()).is_err());

    let mut config = configuration(json!({"mode": "serve", "custody": custody()}));
    for release_id in ["", "Uppercase", "-start", "with_under"] {
        config["releaseId"] = json!(release_id);
        assert!(parse_configuration(&config.to_string()).is_err());
    }
    config["releaseId"] = json!("release-1");
    config["securityDomainId"] = json!("00".repeat(32));
    assert!(parse_configuration(&config.to_string()).is_err());
}

#[test]
fn validates_the_relay_epoch_and_all_authority_pins() {
    let keys = [1, 2, 3].map(|index| {
        let key = SigningKey::from_bytes(&[index; 32].into()).unwrap();
        encode_lower_hex(key.verifying_key().to_sec1_point(false).as_bytes())
    });
    let relay = |epoch, approval_keys| {
        configuration(
            json!({"mode": "relay", "custodyEpoch": epoch, "approvalKeys": approval_keys}),
        )
    };
    assert!(parse_configuration(&relay("1", keys.clone()).to_string()).is_ok());
    assert!(parse_configuration(&relay("0", keys.clone()).to_string()).is_err());
    let repeated = [keys[0].clone(), keys[0].clone(), keys[2].clone()];
    assert!(parse_configuration(&relay("1", repeated).to_string()).is_err());
    let off_curve = [
        keys[0].clone(),
        keys[1].clone(),
        "04".to_owned() + &"00".repeat(64),
    ];
    assert!(parse_configuration(&relay("1", off_curve).to_string()).is_err());
}

#[test]
fn validates_recipient_keys_and_rejects_an_exhausted_rotation_epoch() {
    let recipients: [String; 6] = std::array::from_fn(|_| {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        encode_lower_hex(&key.public_key_to_der().unwrap())
    });
    for deployment in [
        json!({"mode": "initialize", "recipientPublicKeys": recipients}),
        json!({"mode": "rotate", "previous": custody(), "recipientPublicKeys": recipients}),
    ] {
        let mut config = configuration(deployment);
        assert!(parse_configuration(&config.to_string()).is_ok());
        config["deployment"]["recipientPublicKeys"][0] = json!(recipients[1]);
        assert!(parse_configuration(&config.to_string()).is_err());
    }

    let mut previous = custody();
    previous["epoch"] = json!(u64::MAX.to_string());
    let config = configuration(
        json!({"mode": "rotate", "previous": previous, "recipientPublicKeys": recipients}),
    );
    assert_eq!(
        parse_configuration(&config.to_string())
            .err()
            .unwrap()
            .to_string(),
        "custody epoch exhausted",
    );
}
