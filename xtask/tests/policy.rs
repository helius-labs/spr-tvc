use super::*;
use crate::Args;
use clap::Parser;
use serde_json::Value;

fn mainnet_args() -> Args {
    Args::parse_from(["xtask", "prepare", "candidate", "--network", "mainnet"])
}

#[test]
fn authentic_deployment_binds_app_runtime_image_and_manifest() {
    let config = serde_json::from_str(include_str!("../../enclave/deploy/release.json")).unwrap();
    let mut args = mainnet_args();
    args.network = Network::Devnet;
    let devnet = Release {
        args: &args,
        config: &config,
        app: &config.networks.devnet,
    };
    let args = mainnet_args();
    let release = Release {
        args: &args,
        config: &config,
        app: &config.networks.devnet,
    };
    let envelope: Value = serde_json::from_str(include_str!(
        "../../enclave/tests/fixtures/qos-0.12.1-manifest-envelope.json"
    ))
    .unwrap();
    let mut manifest = envelope["manifest"].clone();
    let descriptor = Descriptor {
        pivot_container_image_url: "approved-image".into(),
        expected_pivot_digest: manifest["pivot"]["hash"].as_str().unwrap().into(),
    };
    let key = hex::decode(manifest["namespace"]["quorumKey"].as_str().unwrap()).unwrap();
    let mut api = json!({
        "id": "deployment",
        "organizationId": "org",
        "appId": release.app.app_id,
        "qosVersion": release.config.qos_version,
        "debugMode": false,
        "pivotContainer": { "containerUrl": descriptor.pivot_container_image_url },
    });
    let approve = |release: &Release<'_>, api: &Value, manifest: &Value, key: &[u8]| {
        let mut api = api.clone();
        api["manifest"] =
            json!({ "manifest": STANDARD.encode(serde_json::to_vec(manifest).unwrap()) });
        serde_json::from_value::<TurnkeyDeployment>(api)
            .unwrap()
            .approve(release, "deployment", "org", &descriptor, key)
    };
    let approved = approve(&devnet, &api, &manifest, &key).unwrap();
    assert_eq!(
        approved.manifest_digest,
        "016748a03b94269ade9b75c7b4231a2940cc3c85aabade226a956ea80ab374b0"
    );
    manifest["manifestSet"]["threshold"] = json!("2");
    manifest["shareSet"]["threshold"] = json!("2");
    approve(&release, &api, &manifest, &key).unwrap();
    assert!(approve(&release, &api, &manifest, &vec![0; key.len()]).is_err());
    for (field, value) in [
        ("appId", json!("other-app")),
        ("organizationId", json!("other-org")),
        ("id", json!("other-deployment")),
        ("qosVersion", json!("other-version")),
        ("debugMode", json!(true)),
        ("delete", json!(true)),
        ("pivotContainer", json!({"containerUrl": "other-image"})),
    ] {
        let mut changed = api.clone();
        changed[field] = value;
        assert!(
            approve(&release, &changed, &manifest, &key).is_err(),
            "{field}"
        );
    }
    manifest["shareSet"]["threshold"] = json!("1");
    assert!(approve(&release, &api, &manifest, &key).is_err());
    manifest["shareSet"]["threshold"] = json!("2");
    manifest["manifestSet"]["threshold"] = json!("1");
    assert!(approve(&release, &api, &manifest, &key).is_err());
    api["manifest"] = json!({ "manifest": "broken!" });
    assert!(serde_json::from_value::<TurnkeyDeployment>(api)
        .unwrap()
        .approve(&release, "deployment", "org", &descriptor, &key)
        .is_err());
}

#[test]
fn signed_mainnet_policy_requires_the_exact_candidate_and_distinct_authorities() {
    let now = 100;
    let policy = ReleasePolicy {
        version: API_VERSION,
        release_id: "candidate".into(),
        network: Network::Mainnet,
        security_domain_id: [3; 32],
        accepted_manifest_digests: vec!["aa".repeat(32)],
        accepted_executable_digests: vec!["bb".repeat(32)],
        quorum_key_id: "quorum".into(),
        quorum_key_epoch: 1,
        quorum_public_key: vec![4; 130],
        allowed_operations: OPERATIONS.to_vec(),
        max_encrypted_request_bytes: MAX_ENCRYPTED_REQUEST_BYTES as u32,
        max_encrypted_response_bytes: MAX_ENCRYPTED_RESPONSE_BYTES as u32,
        turnkey_trust_root_id: EXPECTED_TURNKEY_TRUST_ROOT_ID.into(),
        valid_from_ms: now,
        expires_at_ms: now + 10,
        revocation_epoch: 1,
    };
    let mut trust = MainnetTrust {
        release_authorities: PinnedReleaseAuthorities {
            authority_set_id: "mainnet".into(),
            threshold: 2,
            keys: vec![],
            minimum_revocation_epoch: 1,
        },
        qos_identity_pcrs: (0..=3).map(|i| (i, "ab".repeat(48))).collect(),
        security_domain_id: policy.security_domain_id,
        quorum_public_key: vec![],
        maximum_policy_lifetime_ms: 10,
    };
    let signatures = [1, 2]
        .into_iter()
        .map(|i| {
            let secret = [i; 32];
            let key_id = i.to_string();
            let signing_key = SigningKey::from_slice(&secret).unwrap();
            let public = p256::PublicKey::from(signing_key.verifying_key());
            let public_key = public_key_uncompressed(&public).to_vec();
            trust.quorum_public_key.extend_from_slice(&public_key);
            trust.release_authorities.keys.push(ReleaseAuthorityKey {
                key_id: key_id.clone(),
                public_key,
            });
            ReleaseAuthoritySignature {
                key_id,
                signature: sign_release_policy(&policy, &secret).unwrap().to_vec(),
            }
        })
        .collect();
    trust.validate().unwrap();
    let mut signed = SignedReleasePolicy {
        authority_set_id: "mainnet".into(),
        policy: policy.clone(),
        signatures,
    };
    verify_mainnet_policy(&signed, &policy, &trust, now).unwrap();
    assert!(verify_mainnet_policy(&signed, &policy, &trust, 111).is_err());
    let other = ReleasePolicy {
        accepted_manifest_digests: vec!["cc".repeat(32)],
        ..policy.clone()
    };
    assert!(verify_mainnet_policy(&signed, &other, &trust, now).is_err());
    signed.signatures.pop();
    assert!(verify_mainnet_policy(&signed, &policy, &trust, now).is_err());
    assert!(devnet_sign(policy.clone()).is_err());
    let (devnet, authority) = devnet_sign(ReleasePolicy {
        network: Network::Devnet,
        ..policy
    })
    .unwrap();
    verify_signed_release_policy(&devnet, &authority, Network::Devnet, now).unwrap();
}
