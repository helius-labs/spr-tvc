//! What tests of an application here share: a release, and a client's half of the envelope.

use axum::body::Body;
use axum::http::Response;
use ed25519_dalek::{Signer as _, SigningKey};
use http_body_util::BodyExt as _;
use qos_p256::{encrypt::P256EncryptPair, P256Public};
use solana_pubkey::Pubkey;
use spr_keypair::{viewing_key::random_salt, ViewingKey, X25519Pubkey};
use spr_tvc_protocol::constants::API_VERSION;
use spr_tvc_protocol::crypto::{public_key_uncompressed, verify_p256_message};
use spr_tvc_protocol::decryption_service::{
    decrypt_message, service_request_digest, ServiceOperation, ServiceRequest,
};
use spr_tvc_protocol::digest::result_digest;
use spr_tvc_protocol::encoding::parse_strict_json;
use spr_tvc_protocol::types::{
    DecryptItem, DecryptLabel, EncryptedRequest, EncryptedResponse, Network, OperationProofPayload,
    ServiceInfo,
};
use zeroize::Zeroizing;

use crate::Release;

pub fn request(
    info: &ServiceInfo,
    operation: ServiceOperation,
    response_secret: &[u8; 32],
) -> ServiceRequest {
    ServiceRequest {
        version: API_VERSION,
        request_id: [0x77; 32],
        target_release_id: info.release_id.clone(),
        target_manifest_digest: info.manifest_digest,
        target_executable_digest: info.executable_digest,
        quorum_key_id: info.quorum_key_id.clone(),
        quorum_key_epoch: info.quorum_key_epoch,
        client_response_public_key: response_point(response_secret),
        operation,
    }
}

pub fn response_point(secret: &[u8; 32]) -> Vec<u8> {
    public_key_uncompressed(&p256::SecretKey::from_slice(secret).unwrap().public_key()).to_vec()
}

pub fn sign_decrypt(request: &mut ServiceRequest, owner: &SigningKey, network: Network) {
    let digest = service_request_digest(request).unwrap();
    let ServiceOperation::Decrypt {
        signer, signature, ..
    } = &mut request.operation
    else {
        panic!("expected a Decrypt request");
    };
    let address = signer.parse::<Pubkey>().unwrap();
    let message = decrypt_message(&address.to_bytes(), network, &digest);
    *signature = owner.sign(&message).to_bytes();
}

pub fn transfer_output(viewing_public_key: [u8; 33], plaintext: &[u8], slot: u32) -> DecryptItem {
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
        ephemeral_viewing_public_key: transaction.pubkey().as_bytes().to_vec(),
        salt: salt.to_vec(),
        slot_index: slot.into(),
        label: DecryptLabel::Transfer,
    }
}

pub fn release() -> Release {
    Release {
        security_domain_id: [0x11; 32],
        release_id: "release-test".to_owned(),
        quorum_key_id: "quorum-test".to_owned(),
        quorum_key_epoch: 1,
    }
}

/// `plaintext` encrypted to the running Quorum key, as a client sends it.
pub fn encrypt_request(info: &ServiceInfo, plaintext: &str) -> EncryptedRequest {
    let quorum = P256Public::from_bytes(&info.quorum_public_key).expect("quorum key");
    EncryptedRequest {
        version: API_VERSION,
        quorum_key_id: info.quorum_key_id.clone(),
        quorum_key_epoch: info.quorum_key_epoch,
        ciphertext: quorum.encrypt(plaintext.as_bytes()).expect("encrypt"),
    }
}

/// Opens an answer as a client does: checks the App Proof, then decrypts.
pub fn open_response(
    expected_ephemeral: &[u8],
    response: &str,
    response_secret: &[u8; 32],
) -> (OperationProofPayload, Zeroizing<Vec<u8>>) {
    let response: EncryptedResponse = parse_strict_json(response).expect("response");
    let proof = response.tvc_app_proof;
    assert_eq!(proof.public_key, expected_ephemeral);
    let ephemeral = P256Public::from_bytes(&proof.public_key).expect("ephemeral key");
    verify_p256_message(
        &ephemeral.signing_public_key_bytes(),
        proof.proof_payload.as_bytes(),
        &proof.signature,
    )
    .expect("app proof signature");
    let payload: OperationProofPayload =
        parse_strict_json(&proof.proof_payload).expect("proof payload");
    assert_eq!(payload.request_id, response.request_id);
    assert_eq!(
        payload.result_digest,
        result_digest(&response.encrypted_result)
    );
    let plaintext = response_key(response_secret)
        .decrypt(&response.encrypted_result)
        .expect("result");
    (payload, plaintext)
}

pub fn response_key(secret: &[u8; 32]) -> P256EncryptPair {
    P256EncryptPair::from_bytes(&Zeroizing::new(secret.to_vec())).expect("response key")
}

pub async fn body(response: Response<Body>) -> String {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    String::from_utf8(bytes.to_vec()).expect("utf8")
}
