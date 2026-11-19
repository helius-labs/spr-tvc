//! Enrollment: the wallet owner signs, through Turnkey, a Sign-In With Solana
//! message naming this gateway, the wallet, the client key and the time, and
//! the gateway answers with a descriptor for that client key.

use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use spr_tvc_protocol::Network;
use spr_tvc_protocol::constants::MAX_CLOCK_SKEW_MS;
use spr_tvc_protocol::crypto::parse_uncompressed_sec1;

use crate::config::is_canonical_uuid;
use crate::error::ApiError;

pub const STATEMENT: &str = "Authorize this client key to use your private wallet.";
const MAX_ENROLLMENT_AGE_MS: u64 = 5 * 60 * 1_000;

/// A device's enrollment, signed by the wallet owner.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentRequest {
    /// The wallet's Turnkey sub-organization, named after the caller's project.
    pub organization_id: String,
    pub turnkey_wallet_id: String,
    /// The wallet's address, base58.
    pub solana_address: String,
    /// Uncompressed SEC1 P-256 key, lowercase hex.
    pub client_public_key: String,
    /// When the owner signed, in Unix milliseconds; valid for five minutes.
    pub issued_at_ms: u64,
    /// Ed25519 signature by the wallet address over the enrollment's Sign-In With
    /// Solana message, hex.
    pub owner_signature: String,
}

/// A validated enrollment request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentInput {
    pub organization_id: String,
    pub turnkey_wallet_id: String,
    pub solana_address: String,
    pub owner_public_key: [u8; 32],
    pub client_public_key: [u8; 65],
    /// When the owner signed, in Unix ms.
    pub issued_at_ms: u64,
}

pub struct Enrollment {
    network: Network,
    domains: Vec<String>,
}

impl Enrollment {
    /// `domains` are the hosts clients reach this gateway, which serves
    /// `network`, at.
    pub fn new(network: Network, domains: &[String]) -> Self {
        Self {
            network,
            domains: domains.to_vec(),
        }
    }

    /// The enrollment the wallet address signed within the last five minutes.
    pub fn verify(
        &self,
        request: &EnrollmentRequest,
        now_ms: u64,
    ) -> Result<EnrollmentInput, ApiError> {
        let fresh = request.issued_at_ms <= now_ms.saturating_add(MAX_CLOCK_SKEW_MS)
            && now_ms.saturating_sub(request.issued_at_ms) <= MAX_ENROLLMENT_AGE_MS;
        if !fresh {
            return Err(ApiError::StaleEnrollment);
        }
        let input = validate(request)?;
        // The owner signed for the host it called, one of this gateway's.
        for domain in &self.domains {
            let message =
                message(domain, self.network, request).ok_or(ApiError::InvalidEnrollmentRequest)?;
            if verify_owner_signature(&input, &message, &request.owner_signature).is_ok() {
                return Ok(input);
            }
        }
        Err(ApiError::InvalidOwnerEnrollmentSignature)
    }
}

/// The Sign-In With Solana message the wallet owner signs: the gateway's
/// `domain`, the address, [`STATEMENT`], the gateway's network as the chain,
/// the five minutes it is valid for, and the sub-organization, wallet and
/// client key as resources. Only validated fields may go in, so none holds a
/// newline.
pub fn message(domain: &str, network: Network, request: &EnrollmentRequest) -> Option<String> {
    let issued_at = rfc3339_millis(request.issued_at_ms)?;
    let expires_at = rfc3339_millis(request.issued_at_ms.checked_add(MAX_ENROLLMENT_AGE_MS)?)?;
    Some(format!(
        "{domain} wants you to sign in with your Solana account:\n\
         {address}\n\n\
         {STATEMENT}\n\n\
         Version: 1\n\
         Chain ID: {network}\n\
         Issued At: {issued_at}\n\
         Expiration Time: {expires_at}\n\
         Resources:\n\
         - urn:turnkey:organization:{organization}\n\
         - urn:turnkey:wallet:{wallet}\n\
         - urn:spr-tvc:client-key:{client_key}",
        address = request.solana_address,
        organization = request.organization_id,
        wallet = request.turnkey_wallet_id,
        client_key = request.client_public_key,
    ))
}

fn validate(request: &EnrollmentRequest) -> Result<EnrollmentInput, ApiError> {
    let invalid = ApiError::InvalidEnrollmentRequest;
    if !is_canonical_uuid(&request.organization_id)
        || !is_canonical_uuid(&request.turnkey_wallet_id)
    {
        return Err(invalid);
    }
    let owner_public_key = solana_public_key(&request.solana_address).ok_or(invalid)?;
    let client_public_key = client_public_key(&request.client_public_key).ok_or(invalid)?;
    Ok(EnrollmentInput {
        organization_id: request.organization_id.clone(),
        turnkey_wallet_id: request.turnkey_wallet_id.clone(),
        solana_address: request.solana_address.clone(),
        owner_public_key,
        client_public_key,
        issued_at_ms: request.issued_at_ms,
    })
}

/// `2027-01-15T08:00:00.000Z`, as JavaScript's `Date.prototype.toISOString`.
fn rfc3339_millis(ms: u64) -> Option<String> {
    let at = DateTime::<Utc>::from_timestamp_millis(i64::try_from(ms).ok()?)?;
    Some(at.to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn verify_owner_signature(
    input: &EnrollmentInput,
    message: &str,
    signature_hex: &str,
) -> Result<(), ApiError> {
    let invalid = ApiError::InvalidOwnerEnrollmentSignature;
    let mut signature = [0u8; 64];
    hex::decode_to_slice(signature_hex, &mut signature).map_err(|_| invalid)?;
    let owner = VerifyingKey::from_bytes(&input.owner_public_key).map_err(|_| invalid)?;
    owner
        .verify_strict(message.as_bytes(), &Signature::from_bytes(&signature))
        .map_err(|_| invalid)
}

fn solana_public_key(address: &str) -> Option<[u8; 32]> {
    let mut bytes = [0u8; 32];
    let written = bs58::decode(address).onto(&mut bytes).ok()?;
    (written == 32 && bs58::encode(bytes).into_string() == address).then_some(bytes)
}

fn client_public_key(value: &str) -> Option<[u8; 65]> {
    let mut bytes = [0u8; 65];
    let lowercase = value.bytes().all(|b| !b.is_ascii_uppercase());
    hex::decode_to_slice(value, &mut bytes).ok()?;
    parse_uncompressed_sec1(&bytes).ok()?;
    lowercase.then_some(bytes)
}

#[cfg(test)]
#[path = "../tests/unit/owner_enrollment.rs"]
pub(crate) mod tests;
