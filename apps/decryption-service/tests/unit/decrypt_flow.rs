use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer as _, SigningKey};
use qos_p256::P256Pair;
use solana_pubkey::Pubkey;
use spr_keypair::viewing_key::random_salt;
use spr_keypair::{NullifierKey, ViewingKey, X25519Pubkey};
use spr_tvc_enclave::{testing, NETWORK};
use spr_tvc_protocol::crypto::public_key_uncompressed;
use spr_tvc_protocol::decryption_service::decrypt_message;
use spr_tvc_protocol::encoding::{jcs_serialize, parse_strict_json};
use spr_tvc_protocol::types::{
    DecryptItem, DecryptLabel, EncryptedRequest, Network, ServiceInfo, WalletGrant,
};
use tower::ServiceExt as _;
use zeroize::Zeroizing;

use super::*;
use crate::{router, APP};

const RESPONSE_SECRET: [u8; 32] = [0x42; 32];

fn recipient_signer() -> SigningKey {
    SigningKey::from_bytes(&[5; 32])
}

fn response_public_key(secret: &[u8; 32]) -> p256::PublicKey {
    p256::SecretKey::from_slice(secret).unwrap().public_key()
}

fn other(network: Network) -> Network {
    match network {
        Network::Devnet => Network::Mainnet,
        Network::Mainnet => Network::Devnet,
    }
}

fn service_with_quorum_seed(quorum_seed: u8) -> Service {
    let quorum = P256Pair::from_master_seed(&Zeroizing::new([quorum_seed; 32])).unwrap();
    let ephemeral = P256Pair::generate().unwrap();
    let info = testing::release().service_info(&APP, [0x22; 32], [0x33; 32], &quorum, &ephemeral);
    Service::new(info, ephemeral, quorum)
}

fn service() -> Service {
    service_with_quorum_seed(1)
}

fn request(service: &Service, operation: ServiceOperation) -> ServiceRequest {
    let info = &service.info;
    ServiceRequest {
        version: API_VERSION,
        request_id: [0x77; 32],
        target_release_id: info.release_id.clone(),
        target_manifest_digest: info.manifest_digest,
        target_executable_digest: info.executable_digest,
        quorum_key_id: info.quorum_key_id.clone(),
        quorum_key_epoch: info.quorum_key_epoch,
        client_response_public_key: public_key_uncompressed(&response_public_key(&RESPONSE_SECRET))
            .to_vec(),
        operation,
    }
}

fn envelope(service: &Service, request: &ServiceRequest) -> EncryptedRequest {
    testing::encrypt_request(&service.info, &jcs_serialize(request).unwrap(), None)
}

/// Opens an answer as a client does.
fn open(service: &Service, request: &ServiceRequest, response: &str) -> ServiceResult {
    let (payload, plaintext) = testing::open_response(&service.info, response, &RESPONSE_SECRET);
    assert_eq!(payload.r#type, SERVICE_PROOF_TYPE);
    assert_eq!(payload.request_id, request.request_id);
    assert_eq!(
        payload.request_digest,
        service_request_digest(request).unwrap()
    );
    assert_eq!(payload.operation, request.operation.kind());
    assert_eq!(payload.sealed_seed_digest, [0; 32]);
    parse_strict_json(std::str::from_utf8(&plaintext).unwrap()).unwrap()
}

fn call(service: &Service, request: &ServiceRequest) -> Result<ServiceResult, Failure> {
    let response = encrypted_response(service, request)?;
    Ok(open(service, request, &response))
}

fn decrypted(service: &Service, request: &ServiceRequest) -> DecryptedOutputs {
    match call(service, request).unwrap() {
        ServiceResult::Decrypt(outputs) => outputs,
        ServiceResult::PublicKeys { .. } => panic!("expected a Decrypt result"),
    }
}

fn encrypted_response(service: &Service, request: &ServiceRequest) -> Result<String, Failure> {
    let body = jcs_serialize(&envelope(service, request)).unwrap();
    execute(service, body.as_bytes())
}

fn refused(service: &Service, request: &ServiceRequest) {
    assert_eq!(
        encrypted_response(service, request).unwrap_err(),
        Failure::Invalid
    );
}

fn public_keys(service: &Service, owner: &SigningKey) -> ServiceRequest {
    request(
        service,
        ServiceOperation::PublicKeys {
            address: base58(owner),
        },
    )
}

fn base58(owner: &SigningKey) -> String {
    Pubkey::new_from_array(owner.verifying_key().to_bytes()).to_string()
}

/// The service viewing and nullifier public keys of `owner`.
fn service_keys(service: &Service, owner: &SigningKey) -> ([u8; 33], [u8; 32]) {
    let ServiceResult::PublicKeys {
        viewing_public_key,
        nullifier_public_key,
    } = call(service, &public_keys(service, owner)).unwrap()
    else {
        panic!("expected a PublicKeys result");
    };
    (viewing_public_key, nullifier_public_key)
}

/// A `Decrypt` request for `items` that `owner` signed for `network`.
fn decrypt(
    service: &Service,
    owner: &SigningKey,
    network: Network,
    items: Vec<DecryptItem>,
) -> ServiceRequest {
    let mut request = request(
        service,
        ServiceOperation::Decrypt {
            signer: base58(owner),
            signature: [0; 64],
            items,
        },
    );
    let message = decrypt_message(
        &owner.verifying_key().to_bytes(),
        network,
        &service_request_digest(&request).unwrap(),
    );
    let ServiceOperation::Decrypt { signature, .. } = &mut request.operation else {
        unreachable!()
    };
    *signature = owner.sign(&message).to_bytes();
    request
}

fn transfer_output(viewing_public_key: [u8; 33], plaintext: &[u8], slot: u32) -> DecryptItem {
    let transaction = ViewingKey::new();
    let salt = random_salt();
    DecryptItem {
        ciphertext: transaction
            .encrypt_slot(
                &X25519Pubkey::from_bytes(viewing_public_key).unwrap(),
                plaintext,
                salt,
                slot,
            )
            .unwrap(),
        viewing_public_key: viewing_public_key.to_vec(),
        transaction_viewing_public_key: transaction.pubkey().as_bytes().to_vec(),
        salt: salt.to_vec(),
        slot_index: slot.into(),
        label: DecryptLabel::Transfer,
    }
}

#[path = "owner_authorization.rs"]
mod owner_authorization;

#[path = "output_handling.rs"]
mod output_handling;

#[path = "release_binding.rs"]
mod release_binding;

#[path = "response_privacy.rs"]
mod response_privacy;
