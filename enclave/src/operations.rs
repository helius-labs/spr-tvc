//! The encrypted operation endpoint.

use axum::body::Body;
use axum::http::Response;
use axum::response::IntoResponse;
use qos_p256::encrypt::P256EncryptPublic;
use spr_tvc_protocol::constants::API_VERSION;
use std::time::{SystemTime, UNIX_EPOCH};

use spr_tvc_protocol::decryption_service::{
    parse_service_request, service_request_digest, DecryptedOutputs, ServiceOperation,
    ServiceRequest, ServiceResult,
};
use spr_tvc_protocol::types::ServiceInfo;

use crate::cipher::open_ciphertexts;
use crate::request::{open_envelope, respond, Failure};
use crate::{http, keys, owner, Service};

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
    let response_key = P256EncryptPublic::from_bytes(&request.client_response_public_key)
        .map_err(|_| Failure::Invalid)?;

    let request_digest = service_request_digest(&request).map_err(|_| Failure::Invalid)?;
    let result = match &request.operation {
        ServiceOperation::PublicKeys { address } => {
            let address = owner::address_key(address)?.to_bytes();
            let keys = keys::for_address(&service.quorum, &address);
            ServiceResult::PublicKeys {
                viewing_public_key: *keys.viewing.pubkey().as_bytes(),
                nullifier_public_key: keys.nullifier.pubkey().map_err(|_| Failure::Unavailable)?,
            }
        }
        ServiceOperation::Decrypt {
            derivation,
            signer,
            grant,
            signature,
            items,
        } => {
            let address = owner::authorize_decrypt(
                &service.info,
                derivation,
                signer,
                signature,
                grant.as_deref(),
                &request_digest,
                now_ms()?,
            )?;
            let keys = keys::for_address(&service.quorum, &address);
            let plaintexts = open_ciphertexts(&keys.viewing, items)?;
            ServiceResult::Decrypt(DecryptedOutputs {
                nullifier_secret: *keys.nullifier.secret(),
                plaintexts,
            })
        }
    };
    respond(
        &service.ephemeral,
        &request,
        request_digest,
        &response_key,
        &result,
    )
}

fn now_ms() -> Result<u64, Failure> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::Unavailable)?
        .as_millis();
    u64::try_from(millis).map_err(|_| Failure::Unavailable)
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
