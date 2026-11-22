//! The attestation command of the AWS Nitro Secure Module.

#![deny(unsafe_code)]

#[cfg(any(target_os = "linux", test))]
mod codec;
#[cfg(target_os = "linux")]
mod device;

#[cfg(target_os = "linux")]
pub use device::attest;

/// Read the time from a fresh attestation obtained through the local device.
#[cfg(target_os = "linux")]
pub fn now_ms() -> Option<u64> {
    codec::timestamp_ms(&attest(None, None, None).ok()?)
}

#[cfg(test)]
#[path = "../tests/unit/codec.rs"]
mod tests;
