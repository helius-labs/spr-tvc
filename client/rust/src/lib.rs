//! Attested client for the SPR decryption service.
//!
//! The phone, or any other Rust caller, uses [`DecryptionClient::address`] to
//! pay an unregistered owner and [`DecryptionClient::keys`] to open those notes.
//! [`SignViewGrant`] lets that owner name a grantee for at most 30 minutes.
//! [`DecryptionClient`] builds each request from the signed release pin. It
//! checks that the pinned manifest set approved the manifest in the reply,
//! then the Nitro document, PCR0–3, and PCR17, and opens the reply only after
//! the App Proof names the request.
//! [`OperationsClient`] posts `keys` and `decrypt` to
//! `/v1/decryption/operations` and checks the Boot Proof bundled in that reply
//! the same way.

#![forbid(unsafe_code)]

mod attestation;
mod cbor;
#[cfg(feature = "local-dev")]
mod local;
mod operations;
mod service;
mod session;
mod transport;

pub use attestation::{BootProof, IdentityPcrs};
pub use operations::{OperationsClient, OperationsConfig};
pub use service::{DecryptionClient, Note, ServiceKeys, SignViewGrant};
pub use spr_tvc_wire::decryption_service::ViewGrant;
pub use transport::{ReqwestTransport, Transport};

use std::fmt::{Display, Formatter, Result as FmtResult};

use spr_tvc_wire::error::TvcError;
use spr_tvc_wire::release::PinnedReleaseAuthorities;
use spr_tvc_wire::Network;
use spr_tvc_wire::SignedReleasePolicy;

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
    /// The HTTPS origin or API key cannot be used.
    InvalidServiceConfig,
}

impl Display for ClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Protocol(error) => Display::fmt(error, f),
            Self::Transport => f.write_str("Transport"),
            Self::ResponseTooLarge => f.write_str("ResponseTooLarge"),
            Self::Entropy => f.write_str("Entropy"),
            Self::InvalidEnvelope => f.write_str("InvalidEncryptedEnvelope"),
            Self::InvalidServiceConfig => f.write_str("InvalidServiceConfig"),
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

#[cfg(feature = "local-dev")]
impl<T: Transport> DecryptionClient<T, ()> {
    /// Connects to the unattested loopback testkit. The endpoint must be loopback HTTP.
    pub fn connect_local(endpoint: impl Into<String>, transport: T) -> Result<Self, ClientError> {
        let (session, transport) = local::connect(endpoint.into(), transport)?;
        Ok(Self::new(session, transport))
    }
}
