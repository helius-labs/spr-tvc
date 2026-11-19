//! Which addresses have service keys, and what their owner must show.

use ed25519_dalek::{Signature, VerifyingKey};
use solana_pubkey::Pubkey;
use spr_tvc_enclave::Failure;
use spr_tvc_protocol::decryption_service::{decrypt_message, ADDRESS_LEN};
use spr_tvc_protocol::types::Network;

/// Decode an on-curve Ed25519 address and reject small-order keys.
pub(crate) fn address_key(address: &str) -> Result<VerifyingKey, Failure> {
    let address = address.parse::<Pubkey>().map_err(|_| Failure::Invalid)?;
    let key = VerifyingKey::from_bytes(&address.to_bytes()).map_err(|_| Failure::Invalid)?;
    if key.is_weak() {
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
