use std::fs;
use std::path::PathBuf;

use spr_tvc_protocol::encoding::encode_lower_hex;

use super::*;

const APP: App = App {
    operations: &[],
    proof_type: "test",
};

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

fn load(quorum_seed: u8) -> io::Result<Service> {
    let id = encode_lower_hex(&*qos_p256::bytes_os_rng::<16>());
    let dir = std::env::temp_dir().join(format!("spr-tvc-qos-{id}"));
    fs::create_dir(&dir).unwrap();
    let dir = FixtureDir(dir);
    let path = |name: &str| {
        dir.0
            .join(name.trim_start_matches('/'))
            .to_str()
            .unwrap()
            .to_owned()
    };
    let ephemeral = path(EPHEMERAL_KEY_FILE);
    let quorum = path(QUORUM_FILE);
    let manifest = path(MANIFEST_FILE);
    fs::write(&ephemeral, encode_lower_hex(&[EPHEMERAL_SEED; 32])).unwrap();
    fs::write(&quorum, encode_lower_hex(&[quorum_seed; 32])).unwrap();
    fs::write(&manifest, ENVELOPE).unwrap();

    let handles = Handles::new(ephemeral, quorum, manifest, path(PIVOT_FILE));
    Service::load_from(crate::testing::release(), &APP, &handles)
}

#[test]
fn loads_hosted_qos_manifest_and_reports_its_digests() {
    let service = load(0x11).unwrap();
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
        service.info.ephemeral_public_key,
        expected.public_key().to_bytes()
    );
}

#[test]
fn refuses_a_valid_quorum_key_from_another_manifest() {
    let Err(error) = load(0x44) else {
        panic!("startup accepted a quorum key that differs from the manifest");
    };
    assert_eq!(
        error.to_string(),
        "QOS quorum key does not match the approved manifest"
    );
}
