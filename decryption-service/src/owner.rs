//! Which addresses have service keys, and what their owner must show.

use crate::request::Failure;
use ed25519_dalek::{Signature, VerifyingKey};
use solana_pubkey::Pubkey;
use spr_tvc_protocol::decryption_service::{
    accept_view_grant_window, decrypt_message, view_grant_digest, view_grant_message, ViewGrant,
    ADDRESS_LEN,
};
use spr_tvc_protocol::types::{Network, ServiceInfo};

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

/// The address whose service keys open this batch.
///
/// Without a grant, that address is the signer. With a grant, the signer is
/// the grantee and the address is the grant owner.
pub(crate) struct DecryptAuthorization<'a> {
    pub signer: &'a str,
    pub signature: &'a [u8; 64],
    pub request_digest: &'a [u8; 32],
    pub grant: Option<&'a ViewGrant>,
    pub now_ms: u64,
}

impl DecryptAuthorization<'_> {
    pub(crate) fn address(self, info: &ServiceInfo) -> Result<[u8; ADDRESS_LEN], Failure> {
        let signer = verify_decrypt(
            self.signer,
            self.signature,
            info.network,
            self.request_digest,
        )?;
        let Some(grant) = self.grant else {
            return Ok(signer);
        };
        let grantee = address_key(&grant.grantee)?.to_bytes();
        let owner = address_key(&grant.owner)?.to_bytes();
        if grantee != signer
            || owner == grantee
            || grant.network != info.network
            || grant.quorum_key_id != info.quorum_key_id
            || grant.quorum_key_epoch != info.quorum_key_epoch
        {
            return Err(Failure::Invalid);
        }
        accept_view_grant_window(grant.not_before_ms, grant.expiry_ms, self.now_ms)
            .map_err(|_| Failure::Invalid)?;
        let digest = view_grant_digest(grant).map_err(|_| Failure::Invalid)?;
        let owner_key = VerifyingKey::from_bytes(&owner).map_err(|_| Failure::Invalid)?;
        owner_key
            .verify_strict(
                &view_grant_message(&owner, &digest),
                &Signature::from_bytes(&grant.signature),
            )
            .map_err(|_| Failure::Invalid)?;
        Ok(owner)
    }
}
