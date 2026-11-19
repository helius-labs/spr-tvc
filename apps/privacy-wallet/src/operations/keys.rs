//! The wallet's privacy roles as batched functions: opening ciphertexts with
//! the viewing key, deriving nullifiers and merge values from the nullifier
//! secret, and minting per-transaction viewing keys. No answer is a long-lived
//! secret, and no answer is interpreted here: the client decodes plaintexts
//! and matches derived values against what the chain published.

use spr_transaction::instructions::merge::{
    merge_dummy_nullifier, merge_output_blinding, merge_output_key, merge_private_tx_blinding,
};
use spr_tvc_enclave::{check_batch, open_ciphertexts};
use spr_tvc_protocol::types::{DecryptItem, DeriveItem, OperationResult, TransactionKeyItem};

use super::sealed::Roles;
use super::Failure;

pub(super) fn decrypt(roles: &Roles, items: &[DecryptItem]) -> Result<OperationResult, Failure> {
    Ok(OperationResult::Decrypt {
        plaintexts: open_ciphertexts(&roles.viewing_key, items)?,
    })
}

pub(super) fn derive(roles: &Roles, items: &[DeriveItem]) -> Result<OperationResult, Failure> {
    check_batch(items)?;
    let values = items
        .iter()
        .map(|item| match item {
            DeriveItem::Nullifier {
                utxo_hash,
                blinding,
            } => roles
                .nullifier_key
                .nullifier(utxo_hash, blinding)
                .map_err(|_| Failure::Invalid),
            DeriveItem::MergeDummyNullifier {
                first_nullifier,
                slot_index,
            } => {
                let slot = u8::try_from(*slot_index).map_err(|_| Failure::Invalid)?;
                merge_dummy_nullifier(&roles.nullifier_key, first_nullifier, slot)
                    .map_err(|_| Failure::Invalid)
            }
            DeriveItem::MergeOutputBlinding { first_nullifier } => {
                merge_output_blinding(&roles.nullifier_key, first_nullifier)
                    .map_err(|_| Failure::Invalid)
            }
            DeriveItem::MergePrivateTxBlinding { first_nullifier } => {
                merge_private_tx_blinding(&roles.nullifier_key, first_nullifier)
                    .map_err(|_| Failure::Invalid)
            }
            DeriveItem::MergeOutputKey { first_nullifier } => {
                merge_output_key(&roles.nullifier_key, first_nullifier)
                    .map_err(|_| Failure::Invalid)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(OperationResult::Derive { values })
}

/// Per-transaction viewing secrets. The derivation from the viewing key is
/// one way, so a secret returned here opens one transaction and says nothing
/// about the viewing key or any other transaction.
pub(super) fn transaction_keys(
    roles: &Roles,
    items: &[TransactionKeyItem],
) -> Result<OperationResult, Failure> {
    check_batch(items)?;
    let viewing_public_key = roles.viewing_key.pubkey();
    let secrets = items
        .iter()
        .map(|item| {
            if viewing_public_key.as_bytes() != item.viewing_public_key.as_slice() {
                return Err(Failure::Invalid);
            }
            roles
                .viewing_key
                .get_transaction_viewing_key(&item.first_nullifier)
                .map(|key| *key.secret_bytes())
                .map_err(|_| Failure::Invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(OperationResult::TransactionKeys { secrets })
}
