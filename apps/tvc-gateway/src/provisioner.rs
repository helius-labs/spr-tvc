use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use serde::Deserialize;
use spr_tvc_protocol::constants::API_VERSION;
use spr_tvc_protocol::crypto::{sign_p256_prehash, verify_p256_prehash};
use spr_tvc_protocol::digest::descriptor_digest;
use spr_tvc_protocol::{
    ClientGrant, ErrorCode, Network, PinnedReleaseAuthorities, ReleasePolicy, SignedReleasePolicy,
    WalletDescriptor, verify_signed_release_policy,
};
use zeroize::Zeroizing;

use crate::config::{ProvisioningConfig, load_signing_key};
use crate::enrollment::EnrollmentInput;
use crate::error::ApiError;

/// A network's release file, `packages/tvc-wallet/src/releases/<network>.json`,
/// as clients pin it. Its `qosIdentityPcrs` check Boot Proofs, which is the
/// clients' job, so they are not read here.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReleaseFile {
    release_policy: SignedReleasePolicy,
    release_authorities: PinnedReleaseAuthorities,
}

/// Holds the provisioning key and the release policy descriptors are issued
/// under. Signed descriptors are the enclave's only grant of access to a wallet.
pub struct Provisioner {
    secret: Zeroizing<[u8; 32]>,
    public_key: [u8; 65],
    policy: ReleasePolicy,
    descriptor_ttl_ms: u64,
}

impl Provisioner {
    /// Refuses to start under a release file that pins nothing (`null`), is
    /// for another network, or does not verify now.
    pub fn new(config: &ProvisioningConfig, network: Network) -> anyhow::Result<Self> {
        let (secret, public_key) = signing_key(config)?;
        let policy = read_release(&config.release_path, network, now_ms()?)?;
        Ok(Self {
            secret,
            public_key,
            policy,
            descriptor_ttl_ms: config.descriptor_ttl_secs.saturating_mul(1_000),
        })
    }

    /// Refuses to issue descriptors once the release has expired: clients
    /// would refuse its enclave. A new release and deploy fix it.
    pub fn check_current(&self, now_ms: u64) -> Result<(), ApiError> {
        if now_ms > self.policy.expires_at_ms {
            tracing::error!(
                expires_at_ms = self.policy.expires_at_ms,
                "the release policy has expired"
            );
            return Err(ApiError::ReleaseExpired);
        }
        Ok(())
    }

    /// One client key may drive every operation the release allows, for one
    /// Turnkey wallet, until the descriptor lifetime after the owner signed.
    /// The enclave refuses a narrowed or reordered list. The same enrollment
    /// always signs to the same descriptor.
    pub fn sign(&self, input: &EnrollmentInput) -> Result<WalletDescriptor, ApiError> {
        let mut descriptor = WalletDescriptor {
            version: API_VERSION,
            security_domain_id: self.policy.security_domain_id,
            network: self.policy.network,
            turnkey_organization_id: input.organization_id.clone(),
            turnkey_wallet_id: input.turnkey_wallet_id.clone(),
            address: input.solana_address.clone(),
            allowed_clients: vec![ClientGrant {
                client_public_key: input.client_public_key.to_vec(),
                allowed_operations: self.policy.allowed_operations.clone(),
            }],
            expires_at_ms: input.issued_at_ms.saturating_add(self.descriptor_ttl_ms),
            provisioning_signature: Vec::new(),
        };
        let digest = descriptor_digest(&descriptor).map_err(|error| {
            tracing::error!(?error, "descriptor did not canonicalize");
            ApiError::ProvisionerUnavailable
        })?;
        let signature = sign_p256_prehash(&self.secret, &digest).map_err(|error| {
            tracing::error!(?error, "descriptor signing failed");
            ApiError::ProvisionerUnavailable
        })?;
        descriptor.provisioning_signature = signature.to_vec();
        Ok(descriptor)
    }

    /// Accepts a descriptor this provisioner signed under the current release
    /// that has not expired at `now_ms`, with the protocol's clock skew.
    pub fn verify(&self, descriptor: &WalletDescriptor, now_ms: u64) -> Result<(), ApiError> {
        let invalid = ApiError::InvalidDescriptor;
        if descriptor.version != API_VERSION
            || descriptor.security_domain_id != self.policy.security_domain_id
            || descriptor.network != self.policy.network
            || descriptor.allowed_clients.len() != 1
        {
            return Err(invalid);
        }
        let digest = descriptor_digest(descriptor).map_err(|_| invalid)?;
        verify_p256_prehash(
            &self.public_key,
            &digest,
            &descriptor.provisioning_signature,
        )
        .map_err(|_| invalid)?;
        descriptor
            .check_current(now_ms)
            .map_err(|_| ApiError::DescriptorExpired)
    }
}

/// The release policy the release file at `path` pins for `network`, once
/// it verifies at `now_ms` against the authorities the file pins.
pub fn read_release(path: &Path, network: Network, now_ms: u64) -> anyhow::Result<ReleasePolicy> {
    let release: Option<ReleaseFile> = read_json(path)?;
    let Some(release) = release else {
        anyhow::bail!(
            "{} pins no {network} release (it is null): release the {network} enclave with \
             scripts/release.mjs, whose policy phase writes it, and build this image again",
            path.display()
        );
    };
    let policy = &release.release_policy.policy;
    anyhow::ensure!(
        policy.network == network,
        "{} is the {} release, and this gateway serves {network}",
        path.display(),
        policy.network
    );
    verify_signed_release_policy(
        &release.release_policy,
        &release.release_authorities,
        network,
        now_ms,
    )
    .map_err(|error| match error.code {
        ErrorCode::ExpiredRequest => anyhow::anyhow!(
            "the release policy in {} is valid from {} to {} (Unix ms), not now",
            path.display(),
            policy.valid_from_ms,
            policy.expires_at_ms
        ),
        code => anyhow::anyhow!(
            "the release policy in {} does not verify: {code}",
            path.display()
        ),
    })?;
    Ok(release.release_policy.policy)
}

pub fn now_ms() -> anyhow::Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    Ok(u64::try_from(elapsed.as_millis())?)
}

/// The provisioning key, which may also carry a `0x` prefix.
fn signing_key(config: &ProvisioningConfig) -> anyhow::Result<(Zeroizing<[u8; 32]>, [u8; 65])> {
    load_signing_key(
        "provisioning",
        config.private_key.trim().trim_start_matches("0x"),
        &config.expected_public_key,
    )
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

#[cfg(test)]
#[path = "../tests/unit/descriptor_provisioning.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "../tests/unit/release_policy.rs"]
mod release_file_tests;
