//! Attested client for the SPR decryption service.
//!
//! The phone, or any other Rust caller, uses [`DecryptionClient::address`] to
//! pay an unregistered owner and [`DecryptionClient::keys`] to open those notes.
//! [`DecryptionClient`] checks the Nitro document, PCR0–3, PCR17, and the
//! manifest allowlist, and opens a reply only after the App Proof names that
//! request. [`OperationsClient`] is the gatekeeper path. It checks the Boot
//! Proof bundled with `/v1/decryption/session`, then posts `keys` and `decrypt`
//! to `/v1/decryption/operations` and checks the Boot Proof on each reply.

#![forbid(unsafe_code)]

mod attestation;
mod cbor;
mod operations;
mod service;
mod session;
mod transport;

pub use attestation::{BootProof, IdentityPcrs};
pub use operations::{Gatekeeper, OperationsClient};
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
    /// The gatekeeper URL or API key cannot be used.
    InvalidGatekeeperConfig,
}

impl Display for ClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Protocol(error) => Display::fmt(error, f),
            Self::Transport => f.write_str("Transport"),
            Self::ResponseTooLarge => f.write_str("ResponseTooLarge"),
            Self::Entropy => f.write_str("Entropy"),
            Self::InvalidEnvelope => f.write_str("InvalidEncryptedEnvelope"),
            Self::InvalidGatekeeperConfig => f.write_str("InvalidGatekeeperConfig"),
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
