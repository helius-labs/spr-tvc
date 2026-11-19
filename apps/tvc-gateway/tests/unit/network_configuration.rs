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
        "provisioning": { "private_key": "11".repeat(32) },
        "wallet_grant": { "private_key": "06".repeat(32) },
        "turnkey": {
            "boot_proof_api_key": { "public_key": "02", "private_key": "01" },
            "waas_api_key": { "public_key": "02", "private_key": "01" },
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
fn the_devnet_overlay_serves_devnet_at_both_gatekeeper_hosts() {
    let config =
        devnet_config_with(&"a".repeat(MIN_SECRET_LEN)).expect("the committed config loads");
    assert_eq!(config.network, Network::Devnet);
    assert_eq!(config.provisioning.descriptor_ttl_secs, 86_400);
    assert_eq!(
        config
            .decryption_service
            .as_ref()
            .expect("devnet has a decryption-service app")
            .enclave
            .base_url
            .as_str(),
        "https://app-67d544db-f727-4c8b-83fe-74a929ac763b.app.turnkey.cloud"
    );
    assert_eq!(
        config.enrollment.domains,
        ["devnet.helius-rpc.com", "beta-devnet.helius-rpc.com"]
    );
    assert_eq!(
        config.provisioning.release_path,
        Path::new("releases/devnet.json")
    );
    assert_eq!(
        config.provisioning.expected_public_key,
        "046e852f2eb1bc79e2ed3cdb57fa7e2f75720fe53032f6aedcfbdfceb67f635691540564e208ca675f4d8b33291aa1388a0067dadc4f1d04519aab320bbd2cce64"
    );
    assert_eq!(
        config.wallet_grant.expected_public_key,
        "04d92dfa9ba9aafd471ff9ffbf454b9a11b14858a8c2edb4f79a4ea4b4dba8ca5cac9ec06d9bb5576db72d07e087ac6aadf72e4eb31323aafaf9dbd133d26f4dc7"
    );
}

#[test]
fn the_mainnet_overlay_serves_mainnet_at_both_gatekeeper_hosts() {
    let secret = "a".repeat(MIN_SECRET_LEN);
    let config = committed_config("configs/mainnet.yaml", &secret, serde_json::json!({}))
        .expect("the committed mainnet overlay loads");
    assert_eq!(config.network, Network::Mainnet);
    assert_eq!(
        config.enclave.base_url.as_str(),
        "https://app-8a2523d7-feb8-41ee-9587-c202048816ec.app.turnkey.cloud"
    );
    assert!(config.decryption_service.is_none());
    assert_eq!(
        config.turnkey.tvc_organization_id,
        "9b98a0d8-04a4-47a3-9dc3-afa84c686de4"
    );
    assert_eq!(config.provisioning.descriptor_ttl_secs, 86_400);
    assert_eq!(config.enrollment.domains, ["mainnet.helius-rpc.com"]);
    assert_eq!(
        config.provisioning.release_path,
        Path::new("releases/mainnet.json")
    );
    assert_eq!(
        config.provisioning.expected_public_key,
        "04f87ca34fcd2b78f57321c662a66395e400744a1951655ed77fbd1482a84e7590359b5f9b157a84489db68b02984c90b641a05deec3cdfd67dd990aecc89a58e0"
    );
    assert_eq!(
        config.wallet_grant.expected_public_key,
        "048929b53b1b9d0b22be43a306583cdb9233e48da9e260cde61c6f93ceb1e5ea43973c01057c98779d47c03e5a5ed8e2ed1e0bc3d9685bc6deea2474d44fd57d5d"
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
fn a_signing_key_must_be_hex_and_match_its_public_key() {
    let secret = "07".repeat(32);
    let public = hex::encode(public_key_of(&[7; 32]).expect("valid key"));
    let (loaded, loaded_public) =
        load_signing_key("test", &secret, &public).expect("the key loads");
    assert_eq!(
        (*loaded, hex::encode(loaded_public)),
        ([7; 32], public.clone())
    );
    for (secret, public) in [
        (format!("0x{secret}"), public.as_str()),
        ("07".repeat(31), public.as_str()),
        ("00".repeat(32), public.as_str()),
        (secret.clone(), "04"),
    ] {
        assert!(
            load_signing_key("test", &secret, public).is_err(),
            "{secret}"
        );
    }
}

#[test]
fn the_committed_config_requires_a_full_length_origin_secret() {
    assert!(devnet_config_with(&"a".repeat(MIN_SECRET_LEN)).is_ok());
    assert!(devnet_config_with("").is_err());
    assert!(devnet_config_with("Bearer short").is_err());
}
