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

/// Local bind port when QOS did not supply launch arguments.
/// QOS launch arguments override it with port 3000.
pub const DEFAULT_BIND_PORT: u16 = 44030;

#[cfg(feature = "bench")]
#[path = "../benches/support/timing.rs"]
pub mod timing;

#[cfg(test)]
#[path = "../tests/unit/harness.rs"]
mod tests;
