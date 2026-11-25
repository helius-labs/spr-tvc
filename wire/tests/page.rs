//! The empty indexer page used to check that a normal decrypt fits in the 10 MiB body cap.

use spr_keypair::constants::{BLINDING_LEN, SALT_LEN};
use spr_keypair::x25519::X25519_PUBKEY_LEN as SPR_X25519_PUBLIC_KEY_LEN;
use spr_tvc_wire::body_limit::{encrypted_request_http_len, max_inner_len, qos_frame_len};
use spr_tvc_wire::constants::{
    API_VERSION, EMPTY_RECIPIENT_CIPHERTEXT_LEN, NOTES_PER_SIGNATURE, QOS_P256_PUBLIC_LEN,
    RAW_P256_SIGNATURE_LEN, SEC1_UNCOMPRESSED_LEN, TVC_APP_PROOF_SCHEME,
};
use spr_tvc_wire::decryption_service::{
    parse_service_request, ServiceOperation, ServiceRequest, ServiceResult, SERVICE_PROOF_TYPE,
    X25519_PUBLIC_KEY_LEN,
};
use spr_tvc_wire::encoding::jcs_serialize;
use spr_tvc_wire::error::{ErrorCode, TvcError};
use spr_tvc_wire::types::{
    AppProof, DecryptItem, DecryptLabel, EncryptedResponse, KdfMode, OperationKind,
    OperationProofPayload,
};

#[test]
fn key_lengths_match_spr_keypair() {
    assert_eq!(
        spr_tvc_wire::decryption_service::NULLIFIER_SECRET_LEN,
        BLINDING_LEN
    );
    assert_eq!(X25519_PUBLIC_KEY_LEN, SPR_X25519_PUBLIC_KEY_LEN);
}

/// Longest base58 encoding of a 32-byte Solana address.
const MAX_BASE58_ADDRESS_LEN: usize = 44;

/// Canonical `Decrypt` of [`NOTES_PER_SIGNATURE`] empty recipient notes.
///
/// Slots use `u64::MAX` (20 decimal digits) so every slot fits. Release and
/// quorum ids are empty: a real id is shorter than the slack from those slots.
pub fn page_decrypt_request() -> ServiceRequest {
    let item = DecryptItem {
        ciphertext: vec![0; EMPTY_RECIPIENT_CIPHERTEXT_LEN],
        ephemeral_viewing_public_key: vec![0x04; X25519_PUBLIC_KEY_LEN],
        salt: vec![0; SALT_LEN],
        slot_index: u64::MAX,
        label: DecryptLabel::Transfer,
        kdf: KdfMode::HkdfSha256Ctr,
    };
    ServiceRequest {
        version: API_VERSION,
        request_id: [0; 32],
        target_release_id: String::new(),
        target_manifest_digest: [0; 32],
        target_executable_digest: [0; 32],
        quorum_key_id: String::new(),
        quorum_key_epoch: u64::MAX,
        client_response_public_key: vec![0x04; SEC1_UNCOMPRESSED_LEN],
        operation: ServiceOperation::Decrypt {
            signer: "1".repeat(MAX_BASE58_ADDRESS_LEN),
            signature: [0; 64],
            items: vec![item; NOTES_PER_SIGNATURE],
            grant: None,
        },
    }
}

/// Canonical result for the same page: 50-byte plaintexts and the nullifier secret.
fn page_decrypt_result() -> ServiceResult {
    ServiceResult::Decrypt(spr_tvc_wire::decryption_service::DecryptedOutputs {
        nullifier_secret: [0; spr_tvc_wire::decryption_service::NULLIFIER_SECRET_LEN],
        plaintexts: vec![vec![0; EMPTY_RECIPIENT_CIPHERTEXT_LEN]; NOTES_PER_SIGNATURE],
    })
}

pub fn page_inner_json() -> Result<String, TvcError> {
    jcs_serialize(&page_decrypt_request())
}

pub fn page_encrypted_request_len() -> Result<usize, TvcError> {
    let inner = page_inner_json()?;
    encrypted_request_http_len(inner.len(), "", u64::MAX)
}

fn page_encrypted_response_len() -> Result<usize, TvcError> {
    let result = jcs_serialize(&page_decrypt_result())?;
    let proof_payload = jcs_serialize(&OperationProofPayload {
        r#type: SERVICE_PROOF_TYPE.to_owned(),
        version: API_VERSION,
        request_id: [0; 32],
        request_digest: [0; 32],
        result_digest: [0; 32],
        operation: OperationKind::ServiceDecrypt,
    })?;
    let response = EncryptedResponse {
        version: API_VERSION,
        request_id: [0; 32],
        encrypted_result: vec![0; qos_frame_len(result.len())],
        tvc_app_proof: AppProof {
            scheme: TVC_APP_PROOF_SCHEME.to_owned(),
            public_key: vec![0x04; QOS_P256_PUBLIC_LEN],
            proof_payload,
            signature: vec![0; RAW_P256_SIGNATURE_LEN],
        },
    };
    Ok(jcs_serialize(&response)?.len())
}

#[test]
fn an_empty_page_fits_under_the_cap_and_the_reply_is_smaller() {
    use spr_tvc_wire::constants::{MAX_ENCRYPTED_REQUEST_BYTES, MAX_ENCRYPTED_RESPONSE_BYTES};

    let request = page_encrypted_request_len().unwrap();
    let response = page_encrypted_response_len().unwrap();
    let reply = jcs_serialize(&page_decrypt_result()).unwrap();
    assert_eq!(request, 675_814, "the empty-page measurement moved");
    assert!(request < MAX_ENCRYPTED_REQUEST_BYTES as usize);
    assert!(
        response <= request,
        "page reply {response} exceeds the request body {request}"
    );
    assert!(qos_frame_len(reply.len()) as u64 <= MAX_ENCRYPTED_RESPONSE_BYTES);
    assert_eq!(MAX_ENCRYPTED_RESPONSE_BYTES, MAX_ENCRYPTED_REQUEST_BYTES);
    assert_eq!(MAX_ENCRYPTED_REQUEST_BYTES, 10 * 1024 * 1024);
}

#[test]
fn notes_larger_than_the_empty_page_fit_until_the_cap() {
    let page = page_inner_json().unwrap();
    parse_service_request(&page).unwrap();

    let mut room = page_decrypt_request();
    let ServiceOperation::Decrypt { items, .. } = &mut room.operation else {
        unreachable!("page request is a Decrypt");
    };
    items[0].ciphertext.extend(std::iter::repeat_n(0, 64));
    let room = jcs_serialize(&room).unwrap();
    assert!(room.len() > page.len());
    assert!(room.len() <= max_inner_len().unwrap());
    parse_service_request(&room).unwrap();

    let mut over = page_decrypt_request();
    over.target_release_id = "x".repeat(max_inner_len().unwrap() - page.len() + 1);
    let over = jcs_serialize(&over).unwrap();
    assert!(over.len() > max_inner_len().unwrap());
    assert_eq!(
        parse_service_request(&over).unwrap_err().code,
        ErrorCode::RequestTooLarge
    );
}
