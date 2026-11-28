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
    ReleaseNotPinned,
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
///
/// `detail` is set only for [`ErrorCode::BootProofUnverified`]. It is one of
/// `manifest`, `decode`, `shape`, `timestamp`, `bindings`, and `aws-chain`,
/// the same stage names the TypeScript client reports. It is not a second
/// error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TvcError {
    pub code: ErrorCode,
    pub detail: Option<&'static str>,
}

impl TvcError {
    pub const fn new(code: ErrorCode) -> Self {
        Self { code, detail: None }
    }

    pub const fn boot(detail: &'static str) -> Self {
        Self {
            code: ErrorCode::BootProofUnverified,
            detail: Some(detail),
        }
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
