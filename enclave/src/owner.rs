//! Which addresses have service keys, and what their owner must show.

use crate::request::Failure;
use ed25519_dalek::{Signature, VerifyingKey};
use solana_pubkey::Pubkey;
use spr_tvc_protocol::decryption_service::{decrypt_message, ADDRESS_LEN};
use spr_tvc_protocol::types::Network;

/// Decode a canonical Ed25519 signing key in the prime-order subgroup.
pub(crate) fn address_key(address: &str) -> Result<VerifyingKey, Failure> {
    let address = address.parse::<Pubkey>().map_err(|_| Failure::Invalid)?;
    let key = VerifyingKey::from_bytes(&address.to_bytes()).map_err(|_| Failure::Invalid)?;
    let point = key.to_edwards();
    if key.is_weak() || point.compress().as_bytes() != key.as_bytes() || !point.is_torsion_free() {
        return Err(Failure::Invalid);
    }
    Ok(key)
}

/// Return the address after verifying its signature over the network and request digest.
pub(crate) fn verify_decrypt(
    signer_address: &str,
    signature: &[u8; 64],
    network: Network,
    request_digest: &[u8; 32],
) -> Result<[u8; ADDRESS_LEN], Failure> {
    let key = address_key(signer_address)?;
    let address = key.to_bytes();
    key.verify_strict(
        &decrypt_message(&address, network, request_digest),
        &Signature::from_bytes(signature),
    )
    .map_err(|_| Failure::Invalid)?;
    Ok(address)
}
