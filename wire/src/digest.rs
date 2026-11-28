//! Domain-separated wire digests.

use sha2::{Digest, Sha256};

use crate::constants::{RELEASE_POLICY_DOMAIN, RESULT_DIGEST_DOMAIN, SHA256_LEN};

pub fn domain_separated_hash(domain: &[u8], payload: &[u8]) -> [u8; SHA256_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0u8]);
    hasher.update(payload);
    hasher.finalize().into()
}

pub fn sha256(bytes: &[u8]) -> [u8; SHA256_LEN] {
    Sha256::digest(bytes).into()
}

/// Digest of the encrypted result signed in the operation proof.
pub fn result_digest(encrypted_result: &[u8]) -> [u8; SHA256_LEN] {
    domain_separated_hash(RESULT_DIGEST_DOMAIN, encrypted_result)
}

/// Digest of the canonical release policy.
pub fn release_policy_digest(policy_jcs: &[u8]) -> [u8; SHA256_LEN] {
    domain_separated_hash(RELEASE_POLICY_DOMAIN, policy_jcs)
}
