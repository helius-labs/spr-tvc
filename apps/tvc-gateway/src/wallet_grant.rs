//! Wallet grants gate the enclave operations: the enclave refuses a request
//! without a current grant for its descriptor and client key. The gateway
//! signs one for each operation it forwards, so a revoked client key stops at
//! once.

use std::collections::HashSet;

use spr_tvc_protocol::constants::{API_VERSION, MAX_WALLET_GRANT_LIFETIME_MS};
use spr_tvc_protocol::digest::descriptor_digest;
use spr_tvc_protocol::{WalletDescriptor, WalletGrant, client_key_id, sign_wallet_grant};
use zeroize::Zeroizing;

use crate::config::{WalletGrantConfig, load_signing_key};
use crate::error::ApiError;
use crate::project::ProjectId;

pub struct WalletGrants {
    secret: Zeroizing<[u8; 32]>,
    lifetime_ms: u64,
    revoked_client_key_ids: HashSet<String>,
}

impl WalletGrants {
    pub fn new(config: &WalletGrantConfig) -> anyhow::Result<Self> {
        let (secret, _) = load_signing_key(
            "wallet_grant",
            config.private_key.trim(),
            &config.expected_public_key,
        )?;
        let lifetime_ms = config.ttl_secs.saturating_mul(1_000);
        anyhow::ensure!(
            lifetime_ms > 0 && lifetime_ms <= MAX_WALLET_GRANT_LIFETIME_MS,
            "wallet_grant.ttl_secs must be positive and at most {} seconds",
            MAX_WALLET_GRANT_LIFETIME_MS / 1_000
        );
        Ok(Self {
            secret,
            lifetime_ms,
            revoked_client_key_ids: config.revoked_client_key_ids.iter().cloned().collect(),
        })
    }

    /// A grant for `descriptor`'s only client key, attributed to `project`.
    pub fn issue(
        &self,
        project: &ProjectId,
        descriptor: &WalletDescriptor,
        now_ms: u64,
    ) -> Result<WalletGrant, ApiError> {
        let unavailable = ApiError::WalletGrantUnavailable;
        let [client] = descriptor.allowed_clients.as_slice() else {
            return Err(ApiError::InvalidDescriptor);
        };
        let client_key_id = self.unrevoked(client_key_id(&client.client_public_key))?;
        let unsigned = WalletGrant {
            version: API_VERSION,
            descriptor_digest: descriptor_digest(descriptor).map_err(|_| unavailable)?,
            client_key_id,
            project_id: project.as_str().to_owned(),
            issued_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(self.lifetime_ms),
            signature: Vec::new(),
        };
        sign_wallet_grant(unsigned, &self.secret).map_err(|error| {
            tracing::error!(?error, "wallet grant signing failed");
            unavailable
        })
    }

    /// Refuses a revoked client key before any Turnkey call is spent on it.
    pub fn check_client_key(&self, client_public_key: &[u8]) -> Result<(), ApiError> {
        self.unrevoked(client_key_id(client_public_key)).map(|_| ())
    }

    fn unrevoked(&self, client_key_id: String) -> Result<String, ApiError> {
        if self.revoked_client_key_ids.contains(&client_key_id) {
            return Err(ApiError::ClientKeyRevoked);
        }
        Ok(client_key_id)
    }
}

#[cfg(test)]
#[path = "../tests/unit/wallet_grants.rs"]
pub(crate) mod tests;
