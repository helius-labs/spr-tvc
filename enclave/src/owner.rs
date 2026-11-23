//! Which addresses have service keys, and what a signer must show.

use crate::request::Failure;
use ed25519_dalek::{Signature, VerifyingKey};
use solana_pubkey::Pubkey;
use spr_tvc_protocol::decryption_service::{
    accept_view_grant_window, decrypt_message, view_grant_digest, view_grant_message, ViewGrant,
    ADDRESS_LEN,
};
use spr_tvc_protocol::types::ServiceInfo;

/// Decode an on-curve Ed25519 address and reject small-order keys.
pub(crate) fn address_key(address: &str) -> Result<VerifyingKey, Failure> {
    let address = address.parse::<Pubkey>().map_err(|_| Failure::Invalid)?;
    let key = VerifyingKey::from_bytes(&address.to_bytes()).map_err(|_| Failure::Invalid)?;
    if key.is_weak() {
        return Err(Failure::Invalid);
    }
    Ok(key)
}

/// The derivation address whose service keys open this batch.
///
/// `signer` is that address, with no grant, or a grantee named by `grant`.
/// The grant's window is checked at `now_ms`. The enclave keeps no record of it.
pub(crate) fn authorize_decrypt(
    info: &ServiceInfo,
    derivation: &str,
    signer: &str,
    signature: &[u8; 64],
    grant: Option<&ViewGrant>,
    request_digest: &[u8; 32],
    now_ms: u64,
) -> Result<[u8; ADDRESS_LEN], Failure> {
    let derivation_key = address_key(derivation)?;
    let signer_key = address_key(signer)?;
    let derivation_bytes = derivation_key.to_bytes();
    let signer_bytes = signer_key.to_bytes();
    signer_key
        .verify_strict(
            &decrypt_message(&signer_bytes, info.network, request_digest),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| Failure::Invalid)?;

    if signer_bytes == derivation_bytes {
        if grant.is_some() {
            return Err(Failure::Invalid);
        }
        return Ok(derivation_bytes);
    }

    let grant = grant.ok_or(Failure::Invalid)?;
    if grant.derivation != derivation
        || grant.grantee != signer
        || grant.network != info.network
        || grant.quorum_key_id != info.quorum_key_id
        || grant.quorum_key_epoch != info.quorum_key_epoch
    {
        return Err(Failure::Invalid);
    }
    accept_view_grant_window(grant.not_before, grant.expiry, now_ms)
        .map_err(|_| Failure::Invalid)?;
    let grant_digest = view_grant_digest(grant).map_err(|_| Failure::Invalid)?;
    derivation_key
        .verify_strict(
            &view_grant_message(&derivation_bytes, &grant_digest),
            &Signature::from_bytes(&grant.signature),
        )
        .map_err(|_| Failure::Invalid)?;
    Ok(derivation_bytes)
}
