//! Named errors without secret-bearing free-form messages.

use std::fmt::{Display, Formatter, Result as FmtResult};

use serde::{Deserialize, Serialize};

/// Protocol and verification error codes from the specification. The
/// TypeScript client raises the same names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, strum::IntoStaticStr)]
#[cfg_attr(test, derive(strum::VariantArray))]
#[serde(deny_unknown_fields)]
pub enum ErrorCode {
    UnsupportedVersion,
    RequestTooLarge,
    InvalidEncryptedEnvelope,
    ReleaseBindingMismatch,
    QuorumKeyEpochMismatch,
    ExpiredRequest,
    TurnkeyEvidenceInvalid,
    InvalidCanonicalJson,
    DuplicateJsonField,
    UnknownJsonField,
    InvalidHex,
    InvalidDecimal,
    InvalidPublicKey,
    InvalidSignature,
    HighSSignature,
    DerSignatureRejected,
    CompressedKeyRejected,
    DoubleHashRejected,
    BootProofUnverified,
    DiscoveryUntrusted,
    NetworkMismatch,
    ReleasePolicyInvalid,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(self.as_str())
    }
}

/// Typed error. Display is the code name only: no IDs, payloads, or secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TvcError {
    pub code: ErrorCode,
}

impl TvcError {
    pub const fn new(code: ErrorCode) -> Self {
        Self { code }
    }
}

impl Display for TvcError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(&self.code, f)
    }
}

impl std::error::Error for TvcError {}

impl From<ErrorCode> for TvcError {
    fn from(code: ErrorCode) -> Self {
        Self::new(code)
    }
}

#[cfg(test)]
#[path = "../tests/unit/wire_errors.rs"]
mod tests;
