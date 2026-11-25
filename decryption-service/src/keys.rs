//! The service keys of an address.

use hkdf::Hkdf;
use qos_p256::P256Pair;
use sha2::Sha256;
use spr_keypair::{NullifierKey, ViewingKey};
use spr_tvc_protocol::decryption_service::{ADDRESS_LEN, NULLIFIER_SECRET_LEN};
use zeroize::Zeroizing;

const VIEWING_KEY_LABEL: &[u8] = b"TSPP/decryption-service/view_key/x25519/v1";
const NULLIFIER_KEY_LABEL: &[u8] = b"TSPP/decryption-service/nf_key/v1";
const MASTER_SEED_LABEL: &[u8] = b"TSPP/decryption-service/seed/v1";

const MASTER_SEED_LEN: usize = 32;

pub(crate) fn for_address(quorum: &P256Pair, address: &[u8; ADDRESS_LEN]) -> ServiceKeys {
    derive(&master_seed(quorum), address)
}

pub(crate) fn master_seed(quorum: &P256Pair) -> Zeroizing<[u8; MASTER_SEED_LEN]> {
    let mut seed = Zeroizing::new([0u8; MASTER_SEED_LEN]);
    Hkdf::<Sha256>::new(None, quorum.to_master_seed().as_slice())
        .expand(MASTER_SEED_LABEL, seed.as_mut_slice())
        .expect("32 bytes of output");
    seed
}

pub(crate) struct ServiceKeys {
    pub viewing: ViewingKey,
    pub nullifier: NullifierKey,
}

/// HKDF-SHA256 over the master seed, one Expand per key with the address in the info.
pub(crate) fn derive(seed: &[u8; MASTER_SEED_LEN], address: &[u8; ADDRESS_LEN]) -> ServiceKeys {
    let hkdf = Hkdf::<Sha256>::new(None, seed);
    let mut viewing = Zeroizing::new([0u8; 32]);
    hkdf.expand_multi_info(&[VIEWING_KEY_LABEL, address], viewing.as_mut_slice())
        .expect("32 bytes of output");
    let mut nullifier = Zeroizing::new([0u8; NULLIFIER_SECRET_LEN]);
    hkdf.expand_multi_info(&[NULLIFIER_KEY_LABEL, address], nullifier.as_mut_slice())
        .expect("31 bytes of output");
    ServiceKeys {
        viewing: ViewingKey::from_bytes(&viewing),
        nullifier: NullifierKey::from_secret(*nullifier),
    }
}
