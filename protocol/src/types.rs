//! Discovery, encrypted operations, and signed release policies.

use std::fmt::{Display, Formatter, Result as FmtResult};

use serde::{Deserialize, Serialize};

use crate::encoding::{self, decimal_u64, hex};
use crate::error::TvcError;

/// The Solana network the release serves.
/// Every check is equality with the network the checker expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Network {
    Devnet,
    Mainnet,
}

impl Network {
    /// The wire name, which is also the Zolana network name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Mainnet => "mainnet",
        }
    }
}

impl Display for Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(self.as_str())
    }
}

/// What a request asks for, as advertised by `/v1/info` and named in the App
/// Proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum OperationKind {
    ServicePublicKeys,
    ServiceDecrypt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum HealthStatus {
    Healthy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthResponse {
    pub status: HealthStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceInfo {
    pub version: u8,
    pub network: Network,
    #[serde(with = "hex")]
    pub security_domain_id: [u8; 32],
    pub release_id: String,
    #[serde(with = "hex")]
    pub manifest_digest: [u8; 32],
    #[serde(with = "hex")]
    pub executable_digest: [u8; 32],
    #[serde(with = "hex")]
    pub quorum_public_key: Vec<u8>,
    pub quorum_key_id: String,
    #[serde(with = "decimal_u64")]
    pub quorum_key_epoch: u64,
    pub supported_operations: Vec<OperationKind>,
    #[serde(with = "decimal_u64")]
    pub max_encrypted_request_bytes: u64,
    #[serde(with = "decimal_u64")]
    pub max_encrypted_response_bytes: u64,
    pub proof_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum DecryptLabel {
    Transfer,
    RingDeposit,
}

/// One ciphertext to open with a viewing key the enclave holds. The client decodes the output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecryptItem {
    #[serde(with = "hex")]
    pub ciphertext: Vec<u8>,
    /// The sender's ephemeral X25519 viewing key from the transaction or deposit.
    #[serde(with = "hex")]
    pub ephemeral_viewing_public_key: Vec<u8>,
    #[serde(with = "hex")]
    pub salt: Vec<u8>,
    /// Zero for a ring deposit, which carries one envelope.
    #[serde(with = "decimal_u64")]
    pub slot_index: u64,
    pub label: DecryptLabel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedRequest {
    pub version: u8,
    pub quorum_key_id: String,
    #[serde(with = "decimal_u64")]
    pub quorum_key_epoch: u64,
    #[serde(with = "hex")]
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppProof {
    pub scheme: String,
    #[serde(with = "hex")]
    pub public_key: Vec<u8>,
    pub proof_payload: String,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

/// Connection challenge encrypted to the QOS Quorum encryption subkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QosPingChallenge {
    pub r#type: String,
    pub version: u8,
    #[serde(with = "hex")]
    pub challenge: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QosPingRequest {
    pub version: u8,
    #[serde(with = "hex")]
    pub encrypted_challenge: Vec<u8>,
}

/// Proof that the running enclave decrypted with the Quorum key and signed the
/// exact challenge bytes with its Ephemeral signing subkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QosPingResponse {
    pub version: u8,
    pub tvc_app_proof: AppProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedResponse {
    pub version: u8,
    #[serde(with = "hex")]
    pub request_id: [u8; 32],
    #[serde(with = "hex")]
    pub encrypted_result: Vec<u8>,
    pub tvc_app_proof: AppProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationProofPayload {
    pub r#type: String,
    pub version: u8,
    #[serde(with = "hex")]
    pub request_id: [u8; 32],
    #[serde(with = "hex")]
    pub request_digest: [u8; 32],
    #[serde(with = "hex")]
    pub result_digest: [u8; 32],
    pub operation: OperationKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePolicy {
    pub version: u8,
    pub release_id: String,
    pub network: Network,
    #[serde(with = "hex")]
    pub security_domain_id: [u8; 32],
    pub accepted_manifest_digests: Vec<String>,
    pub accepted_executable_digests: Vec<String>,
    pub quorum_key_id: String,
    #[serde(with = "decimal_u64")]
    pub quorum_key_epoch: u64,
    #[serde(with = "hex")]
    pub quorum_public_key: Vec<u8>,
    pub allowed_operations: Vec<OperationKind>,
    pub max_encrypted_request_bytes: u32,
    pub max_encrypted_response_bytes: u32,
    pub turnkey_trust_root_id: String,
    #[serde(with = "decimal_u64")]
    pub valid_from_ms: u64,
    #[serde(with = "decimal_u64")]
    pub expires_at_ms: u64,
    #[serde(with = "decimal_u64")]
    pub revocation_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseAuthoritySignature {
    pub key_id: String,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedReleasePolicy {
    pub policy: ReleasePolicy,
    pub authority_set_id: String,
    pub signatures: Vec<ReleaseAuthoritySignature>,
}

pub fn parse_encrypted_request(json: &str) -> Result<EncryptedRequest, TvcError> {
    encoding::parse_strict_json(json)
}

pub fn parse_qos_ping_request(json: &str) -> Result<QosPingRequest, TvcError> {
    encoding::parse_strict_json(json)
}

pub fn parse_qos_ping_challenge(json: &str) -> Result<QosPingChallenge, TvcError> {
    encoding::parse_strict_json(json)
}
