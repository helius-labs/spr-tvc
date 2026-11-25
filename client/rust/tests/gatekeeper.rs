#[path = "common/mod.rs"]
mod support;

use serde::Deserialize;
use spr_tvc_wire::encoding::{decode_lower_hex_array, parse_strict_json};
use spr_tvc_wire::release::PinnedReleaseAuthorities;
use spr_tvc_wire::SignedReleasePolicy;

use spr_tvc_client::{Gatekeeper, IdentityPcrs, OperationsClient, ReqwestTransport};

use support::{one_note, replay, Key, Tape};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Pin {
    release_policy: SignedReleasePolicy,
    release_authorities: PinnedReleaseAuthorities,
    qos_identity_pcrs: Pcrs,
}

#[derive(Deserialize)]
struct Pcrs {
    #[serde(rename = "0")]
    pcr0: String,
    #[serde(rename = "1")]
    pcr1: String,
    #[serde(rename = "2")]
    pcr2: String,
    #[serde(rename = "3")]
    pcr3: String,
}

#[test]
#[ignore = "needs SPR_E2E_GATEKEEPER_URL, an API key, and SPR_E2E_RELEASE_PIN"]
fn session_opens_one_note() {
    let endpoint = std::env::var("SPR_E2E_GATEKEEPER_URL").expect("SPR_E2E_GATEKEEPER_URL");
    let api_key = std::env::var("HELIUS_API_KEY")
        .or_else(|_| std::env::var("API_KEY"))
        .expect("HELIUS_API_KEY or API_KEY");
    let pin_path = std::env::var("SPR_E2E_RELEASE_PIN").expect("SPR_E2E_RELEASE_PIN");
    let pin: Pin =
        parse_strict_json(&std::fs::read_to_string(pin_path).expect("pin file")).expect("pin");
    let pcrs = IdentityPcrs {
        pcr0: decode_lower_hex_array(&pin.qos_identity_pcrs.pcr0).expect("pcr0"),
        pcr1: decode_lower_hex_array(&pin.qos_identity_pcrs.pcr1).expect("pcr1"),
        pcr2: decode_lower_hex_array(&pin.qos_identity_pcrs.pcr2).expect("pcr2"),
        pcr3: decode_lower_hex_array(&pin.qos_identity_pcrs.pcr3).expect("pcr3"),
    };
    let network = pin.release_policy.policy.network;
    let tape = Tape::new(ReqwestTransport::new().expect("client"));
    let client = OperationsClient::connect(
        network,
        Gatekeeper {
            endpoint,
            api_key: api_key.clone(),
        },
        pin.release_policy,
        pin.release_authorities,
        pcrs,
        &tape,
    )
    .expect("session");
    let owner = Key::from_seed(7);
    let other = Key::from_seed(8);
    let mut keys = client.keys(&owner).expect("keys");
    let (note, plaintext) = one_note(&keys.address());
    let opened = keys.decrypt(std::slice::from_ref(&note)).expect("decrypt");
    assert_eq!(opened, vec![plaintext.clone()]);

    let decrypt = tape
        .posts()
        .into_iter()
        .rfind(|post| post.url.ends_with("/v1/decryption/operations"))
        .expect("decrypt request");
    replay(&tape, &decrypt, Some(&api_key));

    let mut other_keys = client.keys(&other).expect("other keys");
    let wrong = other_keys
        .decrypt(std::slice::from_ref(&note))
        .expect("other owner");
    assert_ne!(wrong, vec![plaintext]);
}
