//! The service keys of an address.

use hkdf::Hkdf;
#[cfg(any(feature = "local-dev", feature = "qos-runtime", test))]
use qos_p256::P256Pair;
use sha2::Sha256;
use spr_keypair::{NullifierKey, ViewingKey};
use spr_tvc_protocol::decryption_service::{ADDRESS_LEN, NULLIFIER_SECRET_LEN};
use zeroize::Zeroizing;

const VIEWING_KEY_LABEL: &[u8] = b"TSPP/decryption-service/view_key/x25519/v1";
const NULLIFIER_KEY_LABEL: &[u8] = b"TSPP/decryption-service/nf_key/v1";
#[cfg(any(feature = "local-dev", feature = "qos-runtime", test))]
const MASTER_SEED_LABEL: &[u8] = b"TSPP/decryption-service/seed/v1";

const MASTER_SEED_LEN: usize = 32;

pub(crate) struct NoteSeed(pub(crate) Zeroizing<[u8; MASTER_SEED_LEN]>);

impl NoteSeed {
    #[cfg(any(feature = "local-dev", feature = "qos-runtime", test))]
    pub(crate) fn from_quorum(quorum: &P256Pair) -> Self {
        Self(master_seed(quorum))
    }

    pub(crate) fn for_address(&self, address: &[u8; ADDRESS_LEN]) -> ServiceKeys {
        derive(&self.0, address)
    }

    #[cfg(any(test, all(feature = "native-nitro", target_os = "linux")))]
    pub(crate) fn canary_key_digest(
        &self,
        domain: &[u8; 32],
        note_seed_commitment: &[u8; 32],
    ) -> std::io::Result<[u8; 32]> {
        use spr_tvc_protocol::digest::sha256;

        let public_signer_seed = sha256(
            &[
                b"SPR/native-nitro/canary-owner/v1".as_slice(),
                domain,
                note_seed_commitment,
            ]
            .concat(),
        );
        let owner = ed25519_dalek::SigningKey::from_bytes(&public_signer_seed).verifying_key();
        let keys = self.for_address(owner.as_bytes());
        let nullifier = keys
            .nullifier
            .pubkey()
            .map_err(|_| std::io::Error::other("derive canary public key"))?;
        Ok(sha256(
            &[
                b"SPR/native-nitro/canary-keys/v1".as_slice(),
                keys.viewing.pubkey().as_bytes(),
                &nullifier,
            ]
            .concat(),
        ))
    }
}

#[cfg(any(feature = "local-dev", feature = "qos-runtime", test))]
fn master_seed(quorum: &P256Pair) -> Zeroizing<[u8; MASTER_SEED_LEN]> {
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
fn derive(seed: &[u8; MASTER_SEED_LEN], address: &[u8; ADDRESS_LEN]) -> ServiceKeys {
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

#[cfg(test)]
#[path = "../tests/unit/key_derivation.rs"]
mod tests;
