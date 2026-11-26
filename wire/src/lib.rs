//! Wire types and cryptographic primitives for the attested decryption service.

#![forbid(unsafe_code)]

pub mod body_limit;
pub mod constants;
pub mod crypto;
pub mod decryption_service;
pub mod digest;
pub mod encoding;
pub mod error;
pub mod release;
pub mod types;

pub use error::{ErrorCode, TvcError};
pub use release::{
    policy_signing_digest, sign_release_policy, verify_signed_release_policy,
    PinnedReleaseAuthorities, ReleaseAuthorityKey,
};
pub use types::{
    AppProof, DecryptItem, DecryptLabel, EncryptedRequest, EncryptedResponse, HealthResponse,
    HealthStatus, KdfMode, ManifestSetMember, ManifestSetPolicy, Network, OperationKind,
    OperationProofPayload, QosPingChallenge, QosPingRequest, QosPingResponse,
    ReleaseAuthoritySignature, ReleasePolicy, ServiceInfo, SignedReleasePolicy,
};

#[cfg(test)]
#[path = "../tests/unit/harness.rs"]
mod unit_tests;
