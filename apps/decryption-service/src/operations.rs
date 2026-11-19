//! The encrypted operation endpoint.

use axum::body::Body;
use axum::http::Response;
use axum::response::IntoResponse;
use qos_p256::encrypt::P256EncryptPublic;
use spr_tvc_enclave::{
    http, open_ciphertexts, open_envelope, respond, Failure, ProofBinding, Service,
};
use spr_tvc_protocol::constants::API_VERSION;
use spr_tvc_protocol::decryption_service::{
    parse_service_request, service_request_digest, DecryptedOutputs, ServiceOperation,
    ServiceRequest, ServiceResult, SERVICE_PROOF_TYPE,
};
use spr_tvc_protocol::types::{OperationKind, ServiceInfo};

use crate::{keys, owner};

pub(crate) const OPERATIONS: [OperationKind; 2] = [
    OperationKind::ServicePublicKeys,
    OperationKind::ServiceDecrypt,
];

pub(crate) fn handle(service: &Service, body: &[u8]) -> Response<Body> {
    match execute(service, body) {
        Ok(response) => http::ok(response),
        Err(failure) => failure.into_response(),
    }
}

fn execute(service: &Service, body: &[u8]) -> Result<String, Failure> {
    let (grant, plaintext) = open_envelope(&service.info, &service.quorum, body)?;
    let request = parse_service_request(&plaintext).map_err(|_| Failure::Invalid)?;
    if grant.is_some() || !targets_release(&request, &service.info) {
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
            signer,
            signature,
            items,
        } => {
            let address =
                owner::verify_decrypt(signer, signature, service.info.network, &request_digest)?;
            let keys = keys::for_address(&service.quorum, &address);
            // An empty batch retrieves the nullifier secret.
            let plaintexts = if items.is_empty() {
                Vec::new()
            } else {
                open_ciphertexts(&keys.viewing, items)?
            };
            ServiceResult::Decrypt(DecryptedOutputs {
                nullifier_secret: *keys.nullifier.secret(),
                plaintexts,
            })
        }
    };
    let binding = ProofBinding {
        proof_type: SERVICE_PROOF_TYPE,
        request_id: request.request_id,
        request_digest,
        operation: request.operation.kind(),
        // Service keys come from the Quorum key.
        sealed_seed_digest: [0; 32],
    };
    respond(&service.ephemeral, binding, &response_key, &result)
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
