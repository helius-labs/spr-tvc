//! The decryption service: requests, results and the messages an owner signs.

use std::fmt;

use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::constants::MAX_ENCRYPTED_RESPONSE_BYTES;
use crate::digest::domain_separated_hash;
use crate::encoding::{self, canonicalize_json_value, decimal_u64, encode_lower_hex, hex};
use crate::error::{ErrorCode, TvcError};
use crate::types::{DecryptItem, Network, OperationKind};

pub const SERVICE_PROOF_TYPE: &str = "spr.tvc.decryption_service.v1";
pub const SERVICE_REQUEST_DIGEST_DOMAIN: &[u8] = b"SPR_TVC_DECRYPTION_SERVICE_REQUEST_V1";

/// Label of the message that authorizes a `Decrypt`.
pub const DECRYPT_LABEL: &str = "TSPP/decryption-service/decrypt/v1";

pub const ADDRESS_LEN: usize = 32;
pub const X25519_PUBLIC_KEY_LEN: usize = 33;
pub const NULLIFIER_SECRET_LEN: usize = 31;

const OFFCHAIN_MESSAGE_MAGIC: &[u8; 16] = b"\xffsolana offchain";

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
        #[serde(with = "decimal_u64")]
        expires_at_ms: u64,
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

struct CanonicalResult<'a>(&'a ServiceResult);

impl Serialize for CanonicalResult<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Field names are ASCII and emitted in JCS order. Values are hex and fixed tags.
        let mut fields = serializer.serialize_struct("ServiceResult", 3)?;
        match self.0 {
            ServiceResult::PublicKeys {
                viewing_public_key,
                nullifier_public_key,
            } => {
                fields.serialize_field("nullifier_public_key", &HexBytes(nullifier_public_key))?;
                fields.serialize_field("type", "PublicKeys")?;
                fields.serialize_field("viewing_public_key", &HexBytes(viewing_public_key))?;
            }
            ServiceResult::Decrypt(result) => {
                fields.serialize_field("nullifier_secret", &HexBytes(&result.nullifier_secret))?;
                fields.serialize_field("plaintexts", &HexPlaintexts(&result.plaintexts))?;
                fields.serialize_field("type", "Decrypt")?;
            }
        }
        fields.end()
    }
}

struct HexBytes<'a>(&'a [u8]);

impl fmt::Display for HexBytes<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut scratch = Zeroizing::new([0; 128]);
        for chunk in self.0.chunks(64) {
            let hex = &mut scratch[..2 * chunk.len()];
            ::hex::encode_to_slice(chunk, &mut *hex).map_err(|_| fmt::Error)?;
            formatter.write_str(std::str::from_utf8(hex).map_err(|_| fmt::Error)?)?;
        }
        Ok(())
    }
}

impl Serialize for HexBytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

struct HexPlaintexts<'a>(&'a [Vec<u8>]);

impl Serialize for HexPlaintexts<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(|bytes| HexBytes(bytes)))
    }
}

impl ServiceResult {
    /// Writes canonical JSON directly into a zeroizing allocation that cannot grow.
    pub fn encode_for_encryption(&self) -> Result<Zeroizing<Vec<u8>>, TvcError> {
        let capacity = match self {
            // Two public keys as hex, plus field names and the operation tag.
            Self::PublicKeys { .. } => 256,
            // Base fields, plus two hex digits, quotes and a separator per entry.
            Self::Decrypt(result) => result.plaintexts.iter().fold(128usize, |size, item| {
                size.saturating_add(item.len().saturating_mul(2).saturating_add(3))
            }),
        }
        .min(MAX_ENCRYPTED_RESPONSE_BYTES as usize);
        let mut bytes = Zeroizing::new(vec![0; capacity]);
        let mut tail = bytes.as_mut_slice();
        serde_json::to_writer(&mut tail, &CanonicalResult(self))
            .map_err(|_| TvcError::new(ErrorCode::InvalidCanonicalJson))?;
        let length = capacity - tail.len();
        bytes.truncate(length);
        Ok(bytes)
    }
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
    let mut message = Vec::with_capacity(85 + payload.len());
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

#[cfg(test)]
#[path = "../tests/unit/decryption_request_binding.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/unit/decryption_result_encoding.rs"]
mod result_tests;
