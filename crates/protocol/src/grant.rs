//! Wallet grants: a short-lived statement, signed by the grant key, that one
//! descriptor and client key may operate. The enclave refuses an operation
//! without a current grant, so an issuer revokes a client key by no longer
//! granting it.

use crate::constants::{API_VERSION, MAX_CLOCK_SKEW_MS, MAX_WALLET_GRANT_LIFETIME_MS};
use crate::crypto::{sign_p256_prehash, verify_p256_prehash};
use crate::digest::{descriptor_digest, wallet_grant_digest};
use crate::error::{ErrorCode, TvcError};
use crate::types::{WalletDescriptor, WalletGrant};

/// Signs `grant`, replacing any signature it carries.
pub fn sign_wallet_grant(
    mut grant: WalletGrant,
    secret: &[u8; 32],
) -> Result<WalletGrant, TvcError> {
    grant.signature = Vec::new();
    grant.signature = sign_p256_prehash(secret, &wallet_grant_digest(&grant)?)?.to_vec();
    Ok(grant)
}

/// Accepts a grant signed by `grant_public` for exactly this descriptor and
/// client key, issued no later than the clock allows, unexpired at `now_ms`,
/// and no longer lived than `MAX_WALLET_GRANT_LIFETIME_MS`.
pub fn verify_wallet_grant(
    grant: &WalletGrant,
    grant_public: &[u8],
    descriptor: &WalletDescriptor,
    client_key_id: &str,
    now_ms: u64,
) -> Result<(), TvcError> {
    let unauthorized = || TvcError::new(ErrorCode::UnauthorizedClient);
    if grant.version != API_VERSION {
        return Err(TvcError::new(ErrorCode::UnsupportedVersion));
    }
    verify_p256_prehash(grant_public, &wallet_grant_digest(grant)?, &grant.signature)
        .map_err(|_| unauthorized())?;
    if grant.descriptor_digest != descriptor_digest(descriptor)?
        || grant.client_key_id != client_key_id
    {
        return Err(unauthorized());
    }
    let lifetime = grant.expires_at_ms.checked_sub(grant.issued_at_ms);
    if !lifetime.is_some_and(|lifetime| lifetime <= MAX_WALLET_GRANT_LIFETIME_MS)
        || grant.issued_at_ms > now_ms.saturating_add(MAX_CLOCK_SKEW_MS)
        || grant.expires_at_ms.saturating_add(MAX_CLOCK_SKEW_MS) < now_ms
    {
        return Err(TvcError::new(ErrorCode::ExpiredRequest));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/wallet_grant_binding.rs"]
mod tests;
