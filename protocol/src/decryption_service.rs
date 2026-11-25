//! The decryption service: requests, results and the messages an owner signs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::body_limit::ensure_within_body;
use crate::digest::domain_separated_hash;
use crate::encoding::{self, canonicalize_json_value, decimal_u64, encode_lower_hex, hex};
use crate::error::{ErrorCode, TvcError};
use crate::types::{DecryptItem, Network, OperationKind};

pub const SERVICE_PROOF_TYPE: &str = "spr.tvc.decryption_service.v1";
pub const SERVICE_REQUEST_DIGEST_DOMAIN: &[u8] = b"SPR_TVC_DECRYPTION_SERVICE_REQUEST_V1";

/// Label of the message that authorizes a `Decrypt`.
pub const DECRYPT_LABEL: &str = "TSPP/decryption-service/decrypt/v1";

pub const ADDRESS_LEN: usize = 32;
pub use spr_keypair::constants::BLINDING_LEN as NULLIFIER_SECRET_LEN;
pub use spr_keypair::x25519::X25519_PUBKEY_LEN as X25519_PUBLIC_KEY_LEN;

const OFFCHAIN_MESSAGE_MAGIC: &[u8; 16] = b"\xffsolana offchain";
/// Solana off-chain message v0 prefix: magic, version, domain, format, signer count, signer, length.
const OFFCHAIN_HEADER_LEN: usize = 16 + 1 + 32 + 1 + 1 + 32 + 2;

/// The plaintext of an `EncryptedRequest` to the decryption service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRequest {
    pub version: u8,
    #[serde(with = "hex")]
    pub request_id: [u8; 32],
    pub target_release_id: String,
    #[serde(with = "hex")]
    pub target_manifest_digest: [u8; 32],
    #[serde(with = "hex")]
    pub target_executable_digest: [u8; 32],
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
    Decrypt {
        signer: String,
        #[serde(with = "hex")]
        signature: [u8; 64],
        items: Vec<DecryptItem>,
    },
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
        nullifier_public_key: [u8; 32],
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
pub fn service_request_digest(request: &ServiceRequest) -> Result<[u8; 32], TvcError> {
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
    request_digest: &[u8; 32],
) -> Vec<u8> {
    let payload = format!(
        "{DECRYPT_LABEL}/{network}/{}",
        encode_lower_hex(request_digest)
    );
    let length = u16::try_from(payload.len()).expect("the payload is short");
    let mut message = Vec::with_capacity(OFFCHAIN_HEADER_LEN + payload.len());
    message.extend_from_slice(OFFCHAIN_MESSAGE_MAGIC);
    message.push(0);
    message.extend_from_slice(&Sha256::digest(DECRYPT_LABEL.as_bytes()));
    message.push(0);
    message.push(1);
    message.extend_from_slice(signer);
    message.extend_from_slice(&length.to_le_bytes());
    message.extend_from_slice(payload.as_bytes());
    message
}
