//! Shared loopback setup for the decryption-client examples.

use ed25519_dalek::Signer;
use spr_keypair::{random_salt, ShieldedAddress, ViewingKey};
use spr_tvc_client::{ClientError, DecryptionClient, Note, OwnerSigner, ReqwestTransport};
use spr_tvc_wire::DecryptLabel;

pub struct Key(ed25519_dalek::SigningKey);

impl Key {
    pub fn pubkey(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}

impl OwnerSigner for Key {
    fn pubkey(&self) -> [u8; 32] {
        Key::pubkey(self)
    }

    fn sign_offchain(&self, message: &[u8]) -> Result<[u8; 64], ClientError> {
        Ok(self.0.sign(message).to_bytes())
    }
}

/// The loopback enclave from `DECRYPTION_SERVICE_LOCAL_ENDPOINT`.
pub fn local_client() -> DecryptionClient<ReqwestTransport, ()> {
    let Ok(endpoint) = std::env::var("DECRYPTION_SERVICE_LOCAL_ENDPOINT") else {
        eprintln!("Set DECRYPTION_SERVICE_LOCAL_ENDPOINT to the loopback enclave.");
        std::process::exit(1);
    };
    DecryptionClient::connect_local(endpoint, ReqwestTransport::new().expect("client"))
        .expect("loopback")
}

/// A local owner. The same seed keeps the examples easy to compare.
pub fn owner() -> Key {
    Key(ed25519_dalek::SigningKey::from_bytes(&[7; 32]))
}

/// One transfer note encrypted to `address`.
pub fn note_for(address: &ShieldedAddress, plaintext: &[u8], slot: u32) -> Note {
    let sender = ViewingKey::new();
    let salt = random_salt();
    Note {
        ciphertext: sender
            .encrypt_slot(&address.viewing_pubkey, plaintext, salt, slot)
            .expect("encrypt"),
        ephemeral_viewing_public_key: *sender.pubkey().as_bytes(),
        salt: salt.to_vec(),
        slot_index: u64::from(slot),
        label: DecryptLabel::Transfer,
    }
}
