//! Attested decryption for Solana Privacy Rings.

#![forbid(unsafe_code)]

#[cfg(not(any(
    feature = "qos-runtime",
    feature = "local-dev",
    all(feature = "native-nitro", target_os = "linux"),
    test
)))]
compile_error!("select a supported enclave runtime");

mod cipher;
#[cfg(all(feature = "native-nitro", target_os = "linux"))]
mod custody;
#[cfg(all(feature = "native-nitro", target_os = "linux"))]
mod custody_relay;
mod http;
mod keys;
#[cfg(feature = "local-dev")]
mod local;
#[cfg(all(feature = "native-nitro", target_os = "linux"))]
mod native_crypto;
#[cfg(all(feature = "native-nitro", target_os = "linux"))]
pub mod nitro;
#[cfg(all(feature = "native-nitro", any(target_os = "linux", test)))]
mod nitro_http;
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

mod wire;
