//! Independently pinned release-policy signatures.
//!
//! Signatures cover `RELEASE_POLICY_DOMAIN || 0x00 || JCS(policy)` with
//! 64-byte raw low-S P-256. Empty signatures fail closed. Duplicate and
//! unknown key IDs do not count toward the threshold. A policy verifies only
//! for the network its verifier expects.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::constants::{API_VERSION, EXPECTED_TURNKEY_TRUST_ROOT_ID};
use crate::crypto::{parse_uncompressed_sec1, sign_p256_prehash, verify_p256_prehash};
use crate::digest::release_policy_digest;
use crate::encoding::{decimal_u64, hex, jcs_serialize};
use crate::error::{ErrorCode, TvcError};
use crate::types::{ManifestSetPolicy, Network, ReleasePolicy, SignedReleasePolicy};

/// Pinned Nitro PCR0–PCR3 values identifying a QOS enclave image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityPcrs {
    #[serde(rename = "0", with = "hex")]
    pub pcr0: [u8; 48],
    #[serde(rename = "1", with = "hex")]
    pub pcr1: [u8; 48],
    #[serde(rename = "2", with = "hex")]
    pub pcr2: [u8; 48],
    #[serde(rename = "3", with = "hex")]
    pub pcr3: [u8; 48],
}

/// Pinned mainnet trust root shared by client verification and release tooling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MainnetTrust {
    pub release_authorities: PinnedReleaseAuthorities,
    pub qos_identity_pcrs: IdentityPcrs,
    #[serde(with = "hex")]
    pub security_domain_id: [u8; 32],
    #[serde(with = "hex")]
    pub quorum_public_key: Vec<u8>,
    pub maximum_policy_lifetime_ms: u64,
}

const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

impl MainnetTrust {
    /// Validate that the trust root itself is well-formed (quorum threshold >= 2,
    /// distinct valid P-256 authority keys, valid Quorum public key, bounded lifetime).
    pub fn validate(&self) -> Result<(), TvcError> {
        let authorities = &self.release_authorities;
        if authorities.authority_set_id.is_empty()
            || authorities.threshold < 2
            || usize::from(authorities.threshold) > authorities.keys.len()
        {
            return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
        }
        let mut ids = HashSet::new();
        let mut keys = HashSet::new();
        for key in &authorities.keys {
            if key.key_id.is_empty()
                || parse_uncompressed_sec1(&key.public_key).is_err()
                || !ids.insert(key.key_id.as_str())
                || !keys.insert(key.public_key.as_slice())
            {
                return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
            }
        }
        if !is_valid_quorum_public_key(&self.quorum_public_key)
            || self.maximum_policy_lifetime_ms == 0
            || self.maximum_policy_lifetime_ms > MAX_SAFE_INTEGER
        {
            return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
        }
        Ok(())
    }

    /// Verify that a mainnet release policy matches this trust root's network,
    /// security domain, Quorum public key, and lifetime bounds.
    pub fn check_policy_bounds(&self, policy: &ReleasePolicy) -> Result<(), TvcError> {
        self.validate()?;
        if policy.network != Network::Mainnet {
            return Err(TvcError::new(ErrorCode::NetworkMismatch));
        }
        if policy.security_domain_id != self.security_domain_id
            || policy.quorum_public_key != self.quorum_public_key
            || policy.valid_from_ms == 0
            || policy.expires_at_ms > MAX_SAFE_INTEGER
        {
            return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
        }
        let lifetime = policy
            .expires_at_ms
            .checked_sub(policy.valid_from_ms)
            .ok_or_else(|| TvcError::new(ErrorCode::ReleasePolicyInvalid))?;
        if lifetime == 0 || lifetime > self.maximum_policy_lifetime_ms {
            return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
        }
        Ok(())
    }

    /// Verify that caller-supplied authorities, PCRs, and signed release policy
    /// all match this pinned mainnet trust root.
    pub fn bind_release(
        &self,
        signed: &SignedReleasePolicy,
        authorities: &PinnedReleaseAuthorities,
        pcrs: &IdentityPcrs,
    ) -> Result<(), TvcError> {
        self.check_policy_bounds(&signed.policy)?;
        if authorities != &self.release_authorities || pcrs != &self.qos_identity_pcrs {
            return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseAuthorityKey {
    pub key_id: String,
    #[serde(with = "hex")]
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinnedReleaseAuthorities {
    pub authority_set_id: String,
    pub threshold: u8,
    pub keys: Vec<ReleaseAuthorityKey>,
    /// Policies below the epoch are revoked.
    #[serde(with = "decimal_u64")]
    pub minimum_revocation_epoch: u64,
}

pub fn policy_signing_digest(policy: &ReleasePolicy) -> Result<[u8; 32], TvcError> {
    let canonical = jcs_serialize(policy)?;
    Ok(release_policy_digest(canonical.as_bytes()))
}

pub fn sign_release_policy(
    policy: &ReleasePolicy,
    secret: &[u8; 32],
) -> Result<[u8; 64], TvcError> {
    sign_p256_prehash(secret, &policy_signing_digest(policy)?)
}

pub fn verify_signed_release_policy(
    signed: &SignedReleasePolicy,
    authorities: &PinnedReleaseAuthorities,
    network: Network,
    now_ms: u64,
) -> Result<(), TvcError> {
    if signed.policy.version != API_VERSION {
        return Err(TvcError::new(ErrorCode::UnsupportedVersion));
    }
    if signed.policy.network != network {
        return Err(TvcError::new(ErrorCode::NetworkMismatch));
    }
    if authorities.threshold == 0 || usize::from(authorities.threshold) > authorities.keys.len() {
        return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
    }
    if signed.authority_set_id != authorities.authority_set_id {
        return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
    }
    if signed.policy.turnkey_trust_root_id != EXPECTED_TURNKEY_TRUST_ROOT_ID
        || !manifest_set_is_pinned(&signed.policy.manifest_set, &signed.policy.namespace)
    {
        return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
    }
    if signed.policy.revocation_epoch < authorities.minimum_revocation_epoch {
        return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
    }
    if now_ms < signed.policy.valid_from_ms || now_ms > signed.policy.expires_at_ms {
        return Err(TvcError::new(ErrorCode::ExpiredRequest));
    }
    if signed.signatures.is_empty() {
        return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
    }

    let mut by_id = HashMap::new();
    let mut public_keys = HashSet::new();
    for key in &authorities.keys {
        if !public_keys.insert(key.public_key.as_slice())
            || by_id
                .insert(key.key_id.as_str(), key.public_key.as_slice())
                .is_some()
        {
            return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
        }
    }

    let mut seen = HashSet::new();
    let mut duplicates = HashSet::new();
    for signature in &signed.signatures {
        if !seen.insert(signature.key_id.as_str()) {
            duplicates.insert(signature.key_id.as_str());
        }
    }

    let digest = policy_signing_digest(&signed.policy)?;
    let mut accepted = 0u8;
    for signature in &signed.signatures {
        if duplicates.contains(signature.key_id.as_str()) {
            continue;
        }
        let Some(public) = by_id.get(signature.key_id.as_str()) else {
            continue;
        };
        verify_p256_prehash(public, &digest, &signature.signature)?;
        accepted = accepted
            .checked_add(1)
            .ok_or_else(|| TvcError::new(ErrorCode::ReleasePolicyInvalid))?;
    }
    if accepted < authorities.threshold {
        return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
    }
    Ok(())
}

fn is_valid_quorum_public_key(bytes: &[u8]) -> bool {
    bytes.len() == 130
        && parse_uncompressed_sec1(&bytes[..65]).is_ok()
        && parse_uncompressed_sec1(&bytes[65..]).is_ok()
}

/// The pinned set is the one the client trusts. It is not read from a Boot Proof.
fn manifest_set_is_pinned(set: &ManifestSetPolicy, namespace: &str) -> bool {
    if namespace.is_empty()
        || namespace.len() > 128
        || set.threshold == 0
        || set.members.is_empty()
        || set.threshold as usize > set.members.len()
    {
        return false;
    }
    let mut aliases = HashSet::new();
    let mut keys = HashSet::new();
    for member in &set.members {
        if member.alias.is_empty()
            || member.alias.len() > 128
            || !is_valid_quorum_public_key(&member.public_key)
            || !aliases.insert(member.alias.as_str())
            || !keys.insert(member.public_key.as_slice())
        {
            return false;
        }
    }
    true
}
