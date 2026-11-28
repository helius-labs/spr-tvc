//! Enclave QOS v2 manifest loading, argument binding, and debug/env refusal tests (INV-01).

use std::fs;
use std::path::PathBuf;

use qos_core::protocol::services::boot::manifest::ManifestEnvelopeV2;
use spr_tvc_wire::encoding::encode_lower_hex;

use std::io;

use qos_core::{EPHEMERAL_KEY_FILE, MANIFEST_FILE, QUORUM_FILE};
use qos_p256::P256Pair;

use crate::service::{require_hosted_pivot, Service};
use crate::tests::testing;

// Synthetic v2 envelope serialized by qos_core 0.12.1's storage writer.
// The embedded manifest uses the Quorum key derived from seed [0x11; 32].
const ENVELOPE: &[u8] = include_bytes!("../fixtures/qos-0.12.1-manifest-envelope.json");
const EPHEMERAL_SEED: u8 = 0x22;

struct FixtureDir(PathBuf);

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn load(quorum_seed: u8, envelope: &[u8]) -> io::Result<Service> {
    load_with(quorum_seed, envelope, &[])
}

fn load_with(quorum_seed: u8, envelope: &[u8], argv: &[String]) -> io::Result<Service> {
    let id = encode_lower_hex(&*qos_p256::bytes_os_rng::<16>());
    let dir = std::env::temp_dir().join(format!("spr-tvc-qos-{id}"));
    fs::create_dir(&dir).unwrap();
    let dir = FixtureDir(dir);
    let path = |name: &str| dir.0.join(name.trim_start_matches('/'));
    let ephemeral = path(EPHEMERAL_KEY_FILE);
    let quorum = path(QUORUM_FILE);
    let manifest = path(MANIFEST_FILE);
    fs::write(&ephemeral, encode_lower_hex(&[EPHEMERAL_SEED; 32])).unwrap();
    fs::write(&quorum, encode_lower_hex(&[quorum_seed; 32])).unwrap();
    fs::write(&manifest, envelope).unwrap();

    Service::load_from(testing::release(), &ephemeral, &quorum, &manifest, argv)
}

#[test]
fn loads_hosted_qos_manifest_and_reports_its_digests() {
    let service = load(0x11, ENVELOPE).unwrap();
    assert_eq!(
        encode_lower_hex(&service.info.manifest_digest),
        "016748a03b94269ade9b75c7b4231a2940cc3c85aabade226a956ea80ab374b0"
    );
    assert_eq!(service.info.executable_digest, [0x55; 32]);
    assert_eq!(
        service.info.quorum_public_key,
        service.quorum.public_key().to_bytes()
    );
    let expected = P256Pair::from_master_seed(&[EPHEMERAL_SEED; 32].into()).unwrap();
    assert_eq!(
        service.ephemeral.public_key().to_bytes(),
        expected.public_key().to_bytes()
    );
}

#[test]
fn refuses_a_valid_quorum_key_from_another_manifest() {
    let Err(error) = load(0x44, ENVELOPE) else {
        panic!("startup accepted a quorum key that differs from the manifest");
    };
    assert_eq!(
        error.to_string(),
        "QOS quorum key does not match the approved manifest"
    );
}

#[test]
fn startup_requires_the_current_qos_envelope_schema() {
    let mut envelope: serde_json::Value = serde_json::from_slice(ENVELOPE).unwrap();
    let manifest = envelope["manifest"].as_object_mut().unwrap();
    assert!(manifest.remove("version").is_some());
    for version in [None, Some("v1")] {
        if let Some(version) = version {
            envelope["manifest"]["version"] = version.into();
        }
        let encoded = serde_json::to_vec(&envelope).unwrap();
        let Err(error) = load(0x11, &encoded) else {
            panic!("startup accepted QOS manifest schema {version:?}");
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

#[test]
fn startup_rejects_launch_arguments_the_manifest_did_not_approve() {
    let Err(error) = load_with(0x11, ENVELOPE, &["--port".into(), "3000".into()]) else {
        panic!("startup accepted launch arguments the manifest did not approve");
    };
    assert!(error.to_string().contains("launch arguments"), "{error}");
}

#[test]
fn startup_rejects_a_flipped_manifest_approval() {
    let mut envelope: serde_json::Value = serde_json::from_slice(ENVELOPE).unwrap();
    let signature = envelope["manifestSetApprovals"][0]["signature"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut bytes = signature.into_bytes();
    let last = bytes.last_mut().unwrap();
    *last = if *last == b'0' { b'1' } else { b'0' };
    envelope["manifestSetApprovals"][0]["signature"] = String::from_utf8(bytes).unwrap().into();
    let Err(error) = load(0x11, &serde_json::to_vec(&envelope).unwrap()) else {
        panic!("startup accepted a flipped manifest approval");
    };
    assert!(error.to_string().contains("approvals"), "{error}");
}

#[test]
fn startup_rejects_debug_mode_and_a_pivot_environment() {
    use qos_core::protocol::services::boot::{PivotEnvValue, PivotEnvVarName};

    let envelope: ManifestEnvelopeV2 = serde_json::from_slice(ENVELOPE).unwrap();
    let pivot = envelope.manifest.pivot;
    require_hosted_pivot(&pivot, &[]).unwrap();

    let mut debug = pivot.clone();
    debug.debug_mode = true;
    assert!(require_hosted_pivot(&debug, &[]).is_err());

    let mut with_env = pivot;
    with_env
        .env
        .insert(
            PivotEnvVarName::try_from("PATH".to_owned()).unwrap(),
            PivotEnvValue::plain("x".into()).unwrap(),
        )
        .unwrap();
    assert!(require_hosted_pivot(&with_env, &[]).is_err());
}
