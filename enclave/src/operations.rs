//! The encrypted operation endpoint.

use axum::body::Body;
use axum::http::Response;
use axum::response::IntoResponse;
use spr_tvc_protocol::constants::API_VERSION;
use spr_tvc_protocol::decryption_service::{
    parse_service_request, service_request_digest, DecryptedOutputs, ServiceOperation,
    ServiceRequest, ServiceResult,
};
use spr_tvc_protocol::types::ServiceInfo;

use crate::cipher::open_ciphertexts;
use crate::request::{open_envelope, respond, Failure};
use crate::{http, owner, Service};

pub(crate) fn handle(service: &Service, body: &[u8]) -> Response<Body> {
    match execute(service, body) {
        Ok(response) => http::ok(response),
        Err(failure) => failure.into_response(),
    }
}

fn execute(service: &Service, body: &[u8]) -> Result<String, Failure> {
    let plaintext = open_envelope(&service.info, &service.quorum, body)?;
    let request = parse_service_request(&plaintext).map_err(|_| Failure::Invalid)?;
    if !targets_release(&request, &service.info) {
        return Err(Failure::Invalid);
    }
    let response_key = service
        .quorum
        .response_key(&request.client_response_public_key)?;

    let request_digest = service_request_digest(&request).map_err(|_| Failure::Invalid)?;
    let result = match &request.operation {
        ServiceOperation::PublicKeys { address } => {
            let address = owner::address_key(address)?.to_bytes();
            let keys = service.note_seed.for_address(&address);
            ServiceResult::PublicKeys {
                viewing_public_key: *keys.viewing.pubkey().as_bytes(),
                nullifier_public_key: keys.nullifier.pubkey().map_err(|_| Failure::Unavailable)?,
            }
        }
        ServiceOperation::Decrypt {
            signer,
            expires_at_ms,
            signature,
            items,
        } => {
            let address =
                owner::verify_decrypt(signer, signature, service.info.network, &request_digest)?;
            require_unexpired(service, *expires_at_ms)?;
            let keys = service.note_seed.for_address(&address);
            let plaintexts = open_ciphertexts(&keys.viewing, items)?;
            ServiceResult::Decrypt(DecryptedOutputs {
                nullifier_secret: *keys.nullifier.secret(),
                plaintexts,
            })
        }
    };
    let response = respond(
        &service.ephemeral,
        &request,
        request_digest,
        &response_key,
        &result,
    )?;
    if let ServiceOperation::Decrypt { expires_at_ms, .. } = request.operation {
        require_unexpired(service, expires_at_ms)?;
    }
    Ok(response)
}

fn require_unexpired(service: &Service, expires_at_ms: u64) -> Result<(), Failure> {
    let now = (service.now_ms)().ok_or(Failure::Unavailable)?;
    if now >= expires_at_ms {
        return Err(Failure::Invalid);
    }
    Ok(())
}

fn targets_release(request: &ServiceRequest, info: &ServiceInfo) -> bool {
    request.version == API_VERSION
        && request.target_release_id == info.release_id
        && request.target_manifest_digest == info.manifest_digest
        && request.target_executable_digest == info.executable_digest
        && request.quorum_key_id == info.quorum_key_id
        && request.quorum_key_epoch == info.quorum_key_epoch
}

#[cfg(test)]
#[path = "../tests/unit/decrypt_flow.rs"]
mod tests;
