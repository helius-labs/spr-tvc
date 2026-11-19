//! Opening pool ciphertexts with a viewing key held in the enclave.

use spr_keypair::viewing_key::Salt;
use spr_keypair::{ViewingKey, X25519Pubkey};
use spr_tvc_protocol::constants::MAX_ITEMS_PER_BATCH;
use spr_tvc_protocol::types::{DecryptItem, DecryptLabel};
use zeroize::Zeroizing;

use crate::Failure;

/// A batch holds between one and `MAX_ITEMS_PER_BATCH` items.
pub fn check_batch<T>(items: &[T]) -> Result<(), Failure> {
    if items.is_empty() || items.len() as u64 > MAX_ITEMS_PER_BATCH {
        return Err(Failure::Invalid);
    }
    Ok(())
}

/// Open every item under the supplied key. The pool cipher has no authentication tag.
pub fn open_ciphertexts(
    viewing: &ViewingKey,
    items: &[DecryptItem],
) -> Result<Vec<Vec<u8>>, Failure> {
    check_batch(items)?;
    let recipient_key = viewing.pubkey();
    // Wipe plaintexts already opened if a later item fails.
    let mut plaintexts = Zeroizing::new(Vec::with_capacity(items.len()));
    for item in items {
        if recipient_key.as_bytes() != item.viewing_public_key.as_slice() {
            return Err(Failure::Invalid);
        }
        let sender_key_bytes = item
            .transaction_viewing_public_key
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
