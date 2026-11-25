//! Attested client for the SPR decryption service.
//!
//! The phone, or any other Rust caller, uses [`DecryptionClient::address`] to
//! pay an unregistered owner and [`DecryptionClient::keys`] to open those notes.
//! Every connection checks the Nitro document, PCR0–3, PCR17, and the manifest
//! allowlist. A reply encrypted to a one-time key is opened only after the
//! App Proof names that request.

#![forbid(unsafe_code)]

mod attestation;
mod cbor;
mod service;
mod session;
mod transport;

pub use attestation::{BootProof, IdentityPcrs};
pub use service::{DecryptionClient, Note, ServiceKeys};
pub use transport::{ReqwestTransport, Transport};

use std::fmt::{Display, Formatter, Result as FmtResult};

use spr_tvc_protocol::error::TvcError;
use spr_tvc_protocol::release::PinnedReleaseAuthorities;
use spr_tvc_protocol::Network;
use spr_tvc_protocol::SignedReleasePolicy;

use crate::session::ConnectConfig;

pub use crate::session::BootProofs;

/// Signs the Solana off-chain message for one `Decrypt`.
pub trait OwnerSigner {
    fn pubkey(&self) -> [u8; 32];
    fn sign_offchain(&self, message: &[u8]) -> Result<[u8; 64], ClientError>;
}

/// Failure without response bytes or key material in the display.
#[derive(Debug)]
pub enum ClientError {
    Protocol(TvcError),
    Transport,
    ResponseTooLarge,
    Entropy,
    /// The response key could not open the ciphertext.
    InvalidEnvelope,
}

impl Display for ClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Protocol(error) => Display::fmt(error, f),
            Self::Transport => f.write_str("Transport"),
            Self::ResponseTooLarge => f.write_str("ResponseTooLarge"),
            Self::Entropy => f.write_str("Entropy"),
            Self::InvalidEnvelope => f.write_str("InvalidEncryptedEnvelope"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<TvcError> for ClientError {
    fn from(error: TvcError) -> Self {
        Self::Protocol(error)
    }
}

impl<T: Transport, B: BootProofs> DecryptionClient<T, B> {
    pub fn connect(
        network: Network,
        endpoint: impl Into<String>,
        release: SignedReleasePolicy,
        authorities: PinnedReleaseAuthorities,
        pcrs: IdentityPcrs,
        transport: T,
        boot_proofs: B,
    ) -> Result<Self, ClientError> {
        let (session, transport) = session::Session::connect(ConnectConfig {
            network,
            endpoint: endpoint.into(),
            release,
            authorities,
            pcrs,
            transport,
            boot_proofs,
            now_ms: None,
        })?;
        Ok(Self::new(session, transport))
    }
}
