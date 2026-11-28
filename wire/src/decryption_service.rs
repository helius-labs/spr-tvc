//! The decryption service: requests, results and the messages an owner signs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::body_limit::ensure_within_body;
use crate::constants::SHA256_LEN;
use crate::digest::domain_separated_hash;
use crate::encoding::{self, canonicalize_json_value, decimal_u64, encode_lower_hex, hex};
use crate::error::{ErrorCode, TvcError};
use crate::types::{DecryptItem, Network, OperationKind};

pub const SERVICE_PROOF_TYPE: &str = "spr.tvc.decryption_service.v1";
pub const SERVICE_REQUEST_DIGEST_DOMAIN: &[u8] = b"SPR_TVC_DECRYPTION_SERVICE_REQUEST_V1";

/// Label of the message that authorizes a `Decrypt`.
pub const DECRYPT_LABEL: &str = "TSPP/decryption-service/decrypt/v1";
/// Label of the message that authorizes a view grant.
pub const VIEW_GRANT_LABEL: &str = "TSPP/decryption-service/view-grant/v1";
pub const VIEW_GRANT_DIGEST_DOMAIN: &[u8] = b"SPR_TVC_VIEW_GRANT_V1";
/// Longest accepted view-grant window. The enclave stores nothing, so expiry is the only revocation.
pub const MAX_VIEW_GRANT_MS: u64 = 30 * 60 * 1000;

pub const ADDRESS_LEN: usize = 32;
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// `spr_keypair::constants::BLINDING_LEN`. `key_lengths_match_spr_keypair` pins this.
pub const NULLIFIER_SECRET_LEN: usize = 31;
/// `spr_keypair::x25519::X25519_PUBKEY_LEN`. `key_lengths_match_spr_keypair` pins this.
pub const X25519_PUBLIC_KEY_LEN: usize = 33;

const OFFCHAIN_MESSAGE_MAGIC: &[u8; 16] = b"\xffsolana offchain";
const OFFCHAIN_VERSION_V0: u8 = 0;
const OFFCHAIN_FORMAT_UTF8: u8 = 0;
const OFFCHAIN_SIGNER_COUNT: u8 = 1;
/// Solana off-chain message v0 prefix: magic, version, domain, format, signer count, signer, length.
const OFFCHAIN_HEADER_LEN: usize =
    OFFCHAIN_MESSAGE_MAGIC.len() + 1 + SHA256_LEN + 1 + 1 + ADDRESS_LEN + size_of::<u16>();

/// The plaintext of an `EncryptedRequest` to the decryption service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRequest {
    pub version: u8,
    #[serde(with = "hex")]
    pub request_id: [u8; SHA256_LEN],
    pub quorum_key_id: String,
    #[serde(with = "decimal_u64")]
    pub quorum_key_epoch: u64,
    #[serde(with = "hex")]
    pub client_response_public_key: Vec<u8>,
    pub operation: ServiceOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum ServiceOperation {
    /// The service public keys of a base58 address.
    PublicKeys { address: String },
    /// Opens `items`; `signature` is the base58 `signer`'s, over [`decrypt_message`].
    ///
    /// Without `grant`, `signer` is the owner. With `grant`, `signer` is the
    /// grantee and the notes opened are the grant owner's.
    Decrypt {
        signer: String,
        #[serde(with = "hex")]
        signature: [u8; ED25519_SIGNATURE_LEN],
        items: Vec<DecryptItem>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant: Option<Box<ViewGrant>>,
    },
}

/// A capability the owner signs locally. The grantee attaches it to `Decrypt`.
///
/// The enclave stores nothing. It accepts the grant while `now` is inside
/// `[not_before_ms, expiry_ms)` and that span is at most [`MAX_VIEW_GRANT_MS`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewGrant {
    pub owner: String,
    pub grantee: String,
    pub network: Network,
    pub quorum_key_id: String,
    #[serde(with = "decimal_u64")]
    pub quorum_key_epoch: u64,
    #[serde(with = "decimal_u64")]
    pub not_before_ms: u64,
    #[serde(with = "decimal_u64")]
    pub expiry_ms: u64,
    #[serde(with = "hex")]
    pub signature: [u8; ED25519_SIGNATURE_LEN],
}

impl ServiceOperation {
    pub fn kind(&self) -> OperationKind {
        match self {
            Self::PublicKeys { .. } => OperationKind::ServicePublicKeys,
            Self::Decrypt { .. } => OperationKind::ServiceDecrypt,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum ServiceResult {
    PublicKeys {
        #[serde(with = "hex")]
        viewing_public_key: [u8; X25519_PUBLIC_KEY_LEN],
        #[serde(with = "hex")]
        nullifier_public_key: [u8; SHA256_LEN],
    },
    Decrypt(DecryptedOutputs),
}

/// Ordered plaintexts and the recipient's service nullifier secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct DecryptedOutputs {
    #[serde(with = "hex")]
    pub nullifier_secret: [u8; NULLIFIER_SECRET_LEN],
    #[serde(with = "hex")]
    pub plaintexts: Vec<Vec<u8>>,
}

impl std::fmt::Debug for DecryptedOutputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DecryptedOutputs(..)")
    }
}

pub fn parse_service_request(json: &str) -> Result<ServiceRequest, TvcError> {
    ensure_within_body(json)?;
    encoding::parse_strict_json(json)
}

/// `H(SERVICE_REQUEST_DIGEST_DOMAIN, JCS(request))`, without a `Decrypt`'s signature.
pub fn service_request_digest(request: &ServiceRequest) -> Result<[u8; SHA256_LEN], TvcError> {
    let mut value = encoding::to_canonical_value(request)?;
    value
        .get_mut("operation")
        .and_then(|operation| operation.as_object_mut())
        .ok_or_else(|| TvcError::new(ErrorCode::InvalidCanonicalJson))?
        .remove("signature");
    let canonical = canonicalize_json_value(&value)?;
    Ok(domain_separated_hash(
        SERVICE_REQUEST_DIGEST_DOMAIN,
        canonical.as_bytes(),
    ))
}

/// What an owner signs for one `Decrypt`: a Solana off-chain message v0 with one signer.
pub fn decrypt_message(
    signer: &[u8; ADDRESS_LEN],
    network: Network,
    request_digest: &[u8; SHA256_LEN],
) -> Vec<u8> {
    let payload = format!(
        "{DECRYPT_LABEL}/{network}/{}",
        encode_lower_hex(request_digest)
    );
    offchain_message(DECRYPT_LABEL, signer, &payload)
}

/// `H(VIEW_GRANT_DIGEST_DOMAIN, JCS(grant))`, without the owner's signature.
pub fn view_grant_digest(grant: &ViewGrant) -> Result<[u8; SHA256_LEN], TvcError> {
    let mut value = encoding::to_canonical_value(grant)?;
    value
        .as_object_mut()
        .ok_or_else(|| TvcError::new(ErrorCode::InvalidCanonicalJson))?
        .remove("signature");
    let canonical = canonicalize_json_value(&value)?;
    Ok(domain_separated_hash(
        VIEW_GRANT_DIGEST_DOMAIN,
        canonical.as_bytes(),
    ))
}

/// What the owner signs for a view grant: a Solana off-chain message v0 with one signer.
pub fn view_grant_message(owner: &[u8; ADDRESS_LEN], grant_digest: &[u8; SHA256_LEN]) -> Vec<u8> {
    let payload = format!("{VIEW_GRANT_LABEL}/{}", encode_lower_hex(grant_digest));
    offchain_message(VIEW_GRANT_LABEL, owner, &payload)
}

/// Accept `now_ms` inside `[not_before_ms, expiry_ms)` when the span is at most [`MAX_VIEW_GRANT_MS`].
pub fn accept_view_grant_window(
    not_before_ms: u64,
    expiry_ms: u64,
    now_ms: u64,
) -> Result<(), TvcError> {
    let Some(span) = expiry_ms.checked_sub(not_before_ms) else {
        return Err(TvcError::new(ErrorCode::ExpiredRequest));
    };
    if span == 0 || span > MAX_VIEW_GRANT_MS || now_ms < not_before_ms || now_ms >= expiry_ms {
        return Err(TvcError::new(ErrorCode::ExpiredRequest));
    }
    Ok(())
}

fn offchain_message(label: &str, signer: &[u8; ADDRESS_LEN], payload: &str) -> Vec<u8> {
    let length = u16::try_from(payload.len()).expect("the payload is short");
    let mut message = Vec::with_capacity(OFFCHAIN_HEADER_LEN + payload.len());
    message.extend_from_slice(OFFCHAIN_MESSAGE_MAGIC);
    message.push(OFFCHAIN_VERSION_V0);
    message.extend_from_slice(&Sha256::digest(label.as_bytes()));
    message.push(OFFCHAIN_FORMAT_UTF8);
    message.push(OFFCHAIN_SIGNER_COUNT);
    message.extend_from_slice(signer);
    message.extend_from_slice(&length.to_le_bytes());
    message.extend_from_slice(payload.as_bytes());
    message
}
