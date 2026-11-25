use figment::providers::Serialized;

use super::*;

/// A committed network overlay with the secrets the environment supplies
/// and `environment` on top, as a deployment loads it.
fn committed_config(
    overlay: &str,
    origin_auth_header: &str,
    environment: serde_json::Value,
) -> anyhow::Result<Config> {
    let secrets = serde_json::json!({
        "origin_auth_header": origin_auth_header,
        "turnkey": {
            "boot_proof_api_key": { "public_key": "02", "private_key": "01" },
        },
    });
    let config: Config = files(Path::new(overlay))?
        .merge(Serialized::defaults(secrets))
        .merge(Serialized::defaults(environment))
        .extract()?;
    config.validate()?;
    Ok(config)
}

fn devnet_config_with(origin_auth_header: &str) -> anyhow::Result<Config> {
    committed_config(
        "configs/devnet.yaml",
        origin_auth_header,
        serde_json::json!({}),
    )
}

#[test]
fn the_devnet_overlay_serves_the_decryption_enclave() {
    let config =
        devnet_config_with(&"a".repeat(MIN_SECRET_LEN)).expect("the committed config loads");
    assert_eq!(config.network, Network::Devnet);
    assert_eq!(
        config.enclave.base_url.as_str(),
        "https://app-67d544db-f727-4c8b-83fe-74a929ac763b.app.turnkey.cloud"
    );
    assert_eq!(
        config.turnkey.tvc_organization_id,
        "9b98a0d8-04a4-47a3-9dc3-afa84c686de4"
    );
}

#[test]
fn the_mainnet_overlay_names_the_network_and_takes_its_enclave_from_the_environment() {
    let secret = "a".repeat(MIN_SECRET_LEN);
    let config = committed_config(
        "configs/mainnet.yaml",
        &secret,
        serde_json::json!({
            "enclave": { "base_url": "https://decryption.example" },
        }),
    )
    .expect("the committed mainnet overlay loads");
    assert_eq!(config.network, Network::Mainnet);
    assert_eq!(config.enclave.base_url, "https://decryption.example");
    assert_eq!(
        config.turnkey.tvc_organization_id,
        "9b98a0d8-04a4-47a3-9dc3-afa84c686de4"
    );
}

#[test]
fn the_shared_config_alone_is_not_a_network() {
    let error =
        files(Path::new("configs/config.yaml")).expect_err("the shared config loads as an overlay");
    assert!(error.to_string().contains("network overlay"), "{error}");
    assert!(
        committed_config("configs/testnet.yaml", "", serde_json::json!({})).is_err(),
        "a missing overlay loads"
    );
}

#[test]
fn the_committed_config_requires_a_full_length_origin_secret() {
    assert!(devnet_config_with(&"a".repeat(MIN_SECRET_LEN)).is_ok());
    assert!(devnet_config_with("").is_err());
    assert!(devnet_config_with("Bearer short").is_err());
}
