//! Reject a canonical request whose encrypted HTTP body would exceed the cap.

use std::sync::OnceLock;

use crate::constants::{API_VERSION, QOS_ENVELOPE_OVERHEAD};
use crate::encoding::jcs_serialize;
use crate::error::{ErrorCode, TvcError};
use crate::types::EncryptedRequest;

/// Bytes of a QOS frame around `plaintext_len` bytes.
fn qos_frame_len(plaintext_len: usize) -> usize {
    plaintext_len + QOS_ENVELOPE_OVERHEAD
}

/// HTTP body of an `EncryptedRequest` whose ciphertext is a QOS frame of `inner_len`.
///
/// The frame's contents do not change the JSON length. `quorum_key_id` and
/// `quorum_key_epoch` are the outer request's. The cap uses an empty id and
/// epoch `u64::MAX`, which is the longest epoch.
fn encrypted_request_http_len(inner_len: usize) -> Result<usize, TvcError> {
    let request = EncryptedRequest {
        version: API_VERSION,
        quorum_key_id: String::new(),
        quorum_key_epoch: u64::MAX,
        ciphertext: vec![0; qos_frame_len(inner_len)],
    };
    Ok(jcs_serialize(&request)?.len())
}

/// Largest canonical inner JSON whose encrypted HTTP body fits in the cap.
///
/// Each extra plaintext byte adds two hex characters, and the wrapper around an
/// empty plaintext is fixed for an empty Quorum id and epoch `u64::MAX`.
fn max_inner_len() -> Result<usize, TvcError> {
    static LEN: OnceLock<usize> = OnceLock::new();
    if let Some(len) = LEN.get() {
        return Ok(*len);
    }
    let wrapper = encrypted_request_http_len(0)?;
    let cap = usize::try_from(crate::constants::MAX_ENCRYPTED_REQUEST_BYTES)
        .expect("the body cap fits in usize");
    let len = cap.saturating_sub(wrapper) / 2;
    Ok(*LEN.get_or_init(|| len))
}

pub(crate) fn ensure_within_body(json: &str) -> Result<(), TvcError> {
    if json.len() > max_inner_len()? {
        Err(TvcError::new(ErrorCode::RequestTooLarge))
    } else {
        Ok(())
    }
}
