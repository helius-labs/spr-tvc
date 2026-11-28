//! Opens one note at a deployed endpoint.
//!
//! Set `SPR_E2E_ENDPOINT`, `HELIUS_API_KEY` or `API_KEY`, and
//! `SPR_E2E_RELEASE_PIN` to the signed release JSON.

use serde::Deserialize;
use spr_tvc_client::{IdentityPcrs, OperationsClient, OperationsConfig, ReqwestTransport};
use spr_tvc_rust_example::{note_for, owner};
use spr_tvc_wire::encoding::{decode_lower_hex_array, parse_strict_json};
use spr_tvc_wire::release::PinnedReleaseAuthorities;
use spr_tvc_wire::SignedReleasePolicy;

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

fn main() {
    let endpoint = env("SPR_E2E_ENDPOINT");
    let api_key = std::env::var("HELIUS_API_KEY")
        .or_else(|_| std::env::var("API_KEY"))
        .unwrap_or_else(|_| env("HELIUS_API_KEY"));
    let pin: Pin =
        parse_strict_json(&std::fs::read_to_string(env("SPR_E2E_RELEASE_PIN")).expect("pin file"))
            .expect("pin");
    let pcrs = IdentityPcrs {
        pcr0: decode_lower_hex_array(&pin.qos_identity_pcrs.pcr0).expect("pcr0"),
        pcr1: decode_lower_hex_array(&pin.qos_identity_pcrs.pcr1).expect("pcr1"),
        pcr2: decode_lower_hex_array(&pin.qos_identity_pcrs.pcr2).expect("pcr2"),
        pcr3: decode_lower_hex_array(&pin.qos_identity_pcrs.pcr3).expect("pcr3"),
    };
    let client = OperationsClient::connect(
        pin.release_policy.policy.network,
        OperationsConfig { endpoint, api_key },
        pin.release_policy,
        pin.release_authorities,
        pcrs,
        ReqwestTransport::new().expect("client"),
    )
    .expect("session");
    let owner = owner();
    let mut keys = client.keys(&owner).expect("keys");
    let plaintext = b"ten usdc".to_vec();
    let note = note_for(&keys.address(), &plaintext, 0);
    let opened = keys.decrypt(std::slice::from_ref(&note)).expect("decrypt");
    assert_eq!(opened, vec![plaintext]);
    println!(
        "ok plaintext={}",
        std::str::from_utf8(&opened[0]).expect("utf-8")
    );
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        eprintln!("Set {name}");
        std::process::exit(1);
    })
}
