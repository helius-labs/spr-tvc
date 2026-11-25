//! Opening pool ciphertexts with a viewing key held in the enclave.

use spr_keypair::viewing_key::Salt;
use spr_keypair::{ViewingKey, X25519Pubkey};
use spr_tvc_protocol::types::{DecryptItem, DecryptLabel};
use zeroize::Zeroizing;

use crate::request::Failure;

/// Open every item under the supplied key.
///
/// The pool cipher is `spr-keypair`'s `ctr_apply` at the commit pinned in the
/// workspace: HKDF-SHA256 yields 44 bytes, and AES-256-CTR starts at
/// `nonce || 2`. It has no authentication tag.
pub(crate) fn open_ciphertexts(
    viewing: &ViewingKey,
    items: &[DecryptItem],
) -> Result<Vec<Vec<u8>>, Failure> {
    // Wipe plaintexts already opened if a later item fails.
    let mut plaintexts = Zeroizing::new(Vec::with_capacity(items.len()));
    for item in items {
        let sender_key_bytes = item
            .ephemeral_viewing_public_key
            .as_slice()
            .try_into()
            .map_err(|_| Failure::Invalid)?;
        let sender_key =
            X25519Pubkey::from_bytes(sender_key_bytes).map_err(|_| Failure::Invalid)?;
        let salt: Salt = item
            .salt
            .as_slice()
            .try_into()
            .map_err(|_| Failure::Invalid)?;
        let plaintext = match item.label {
            DecryptLabel::Transfer => {
                let slot = u32::try_from(item.slot_index).map_err(|_| Failure::Invalid)?;
                viewing.decrypt_utxo(&item.ciphertext, &sender_key, salt, slot)
            }
            DecryptLabel::RingDeposit if item.slot_index == 0 => {
                viewing.decrypt_ring_deposit(&item.ciphertext, &sender_key, salt)
            }
            DecryptLabel::RingDeposit => return Err(Failure::Invalid),
        }
        .map_err(|_| Failure::Invalid)?;
        plaintexts.push(plaintext);
    }
    Ok(std::mem::take(&mut *plaintexts))
}

#[cfg(test)]
mod tests {
    /// The pool cipher and the protocol note both name this Zolana commit.
    const CIPHER_COMMIT: &str = "c5297afa13e8bfb6edadf6408304ef3fc2f8c676";

    #[test]
    fn the_cipher_commit_matches_the_workspace_pin_and_the_protocol_note() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let workspace = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
        let readme = std::fs::read_to_string(root.join("protocol/README.md")).unwrap();
        let enclave = std::fs::read_to_string(root.join("enclave/Cargo.toml")).unwrap();
        assert!(
            workspace.contains(&format!("rev = \"{CIPHER_COMMIT}\"")),
            "workspace spr-keypair pin"
        );
        assert!(
            readme.contains(CIPHER_COMMIT),
            "protocol README cipher commit"
        );
        assert!(enclave.contains("spr-keypair.workspace = true"));
        assert!(
            !enclave.contains(CIPHER_COMMIT),
            "the enclave takes spr-keypair from the workspace pin"
        );
    }
}
