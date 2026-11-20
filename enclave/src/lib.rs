//! Attested decryption for Solana Privacy Rings.

#![forbid(unsafe_code)]

mod cipher;
mod http;
mod keys;
#[cfg(feature = "local-dev")]
mod local;
mod operations;
mod owner;
mod release;
mod request;
mod service;

#[cfg(feature = "local-dev")]
pub use local::service as local_unattested_service;
pub use release::Release;
pub use service::{serve, Service};

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod testing;
