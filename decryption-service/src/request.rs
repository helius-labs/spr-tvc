//! The encrypted request every operation arrives in, and its proof-carrying answer.

use axum::body::Body;
use axum::http::Response;
use axum::response::IntoResponse;
use p256::ecdsa::Signature;
use qos_p256::encrypt::P256EncryptPublic;
use qos_p256::P256Pair;
use spr_tvc_wire::constants::{API_VERSION, MAX_ENCRYPTED_RESPONSE_BYTES, TVC_APP_PROOF_SCHEME};
use spr_tvc_wire::decryption_service::{ServiceRequest, ServiceResult, SERVICE_PROOF_TYPE};
use spr_tvc_wire::digest::result_digest;
use spr_tvc_wire::encoding::{is_rfc8785, jcs_serialize};
use spr_tvc_wire::types::{
    parse_encrypted_request, AppProof, EncryptedResponse, OperationProofPayload, ServiceInfo,
};
use zeroize::Zeroizing;

use crate::http::PublicError;

/// Why a request got no result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// Malformed or not authorized; a generic 400.
    Invalid,
    /// The enclave cannot serve; a generic 503.
    Unavailable,
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response<Body> {
        match self {
            Self::Invalid => PublicError::InvalidRequest,
            Self::Unavailable => PublicError::Unavailable,
        }
        .into_response()
    }
}

/// Opens a request's envelope and returns its canonical JSON plaintext.
pub(crate) fn open_envelope(
    info: &ServiceInfo,
    quorum: &P256Pair,
    body: &[u8],
) -> Result<Zeroizing<String>, Failure> {
    let body = std::str::from_utf8(body).map_err(|_| Failure::Invalid)?;
    let encrypted = parse_encrypted_request(body).map_err(|_| Failure::Invalid)?;
    if encrypted.version != API_VERSION
        || encrypted.quorum_key_id != info.quorum_key_id
        || encrypted.quorum_key_epoch != info.quorum_key_epoch
    {
        return Err(Failure::Invalid);
    }
    let plaintext = Zeroizing::new(
        quorum
            .decrypt(&encrypted.ciphertext)
            .map_err(|_| Failure::Invalid)?,
    );
    let plaintext = std::str::from_utf8(&plaintext).map_err(|_| Failure::Invalid)?;
    if !is_rfc8785(plaintext) {
        return Err(Failure::Invalid);
    }
    Ok(Zeroizing::new(plaintext.to_owned()))
}

/// Encrypts `result` to the response key under an App Proof the Ephemeral key signs.
pub(crate) fn respond(
    ephemeral: &P256Pair,
    request: &ServiceRequest,
    request_digest: [u8; 32],
    response_key: &P256EncryptPublic,
    result: &ServiceResult,
) -> Result<String, Failure> {
    let plaintext = Zeroizing::new(jcs_serialize(result).map_err(|_| Failure::Unavailable)?);
    let encrypted_result = response_key
        .encrypt(plaintext.as_bytes())
        .map_err(|_| Failure::Unavailable)?;
    if encrypted_result.len() as u64 > MAX_ENCRYPTED_RESPONSE_BYTES {
        return Err(Failure::Unavailable);
    }

    let proof_payload = jcs_serialize(&OperationProofPayload {
        r#type: SERVICE_PROOF_TYPE.to_owned(),
        version: API_VERSION,
        request_id: request.request_id,
        request_digest,
        result_digest: result_digest(&encrypted_result),
        operation: request.operation.kind(),
    })
    .map_err(|_| Failure::Unavailable)?;
    let signature = sign_ephemeral_low_s(ephemeral, proof_payload.as_bytes())?;
    jcs_serialize(&EncryptedResponse {
        version: API_VERSION,
        request_id: request.request_id,
        encrypted_result,
        tvc_app_proof: AppProof {
            scheme: TVC_APP_PROOF_SCHEME.to_owned(),
            public_key: ephemeral.public_key().to_bytes(),
            proof_payload,
            signature,
        },
    })
    .map_err(|_| Failure::Unavailable)
}

pub(crate) fn sign_ephemeral_low_s(
    ephemeral: &P256Pair,
    message: &[u8],
) -> Result<Vec<u8>, Failure> {
    let raw = ephemeral.sign(message).map_err(|_| Failure::Unavailable)?;
    let signature = Signature::from_slice(&raw).map_err(|_| Failure::Unavailable)?;
    Ok(signature.normalize_s().to_bytes().to_vec())
}
