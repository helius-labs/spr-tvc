//! Domain-separated wire digests.

use sha2::{Digest, Sha256};

use crate::constants::{RELEASE_POLICY_DOMAIN, RESULT_DIGEST_DOMAIN};

pub fn domain_separated_hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0u8]);
    hasher.update(payload);
    hasher.finalize().into()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// `request_digest` omits only `authorization.signature`; `client_key_id` stays.
pub fn result_digest(encrypted_result: &[u8]) -> [u8; 32] {
    domain_separated_hash(RESULT_DIGEST_DOMAIN, encrypted_result)
}

/// Digest of the exact sealed-seed wire bytes.
pub fn release_policy_digest(policy_jcs: &[u8]) -> [u8; 32] {
    domain_separated_hash(RELEASE_POLICY_DOMAIN, policy_jcs)
}
