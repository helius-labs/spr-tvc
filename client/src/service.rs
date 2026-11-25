//! Public keys, note decryption, and the nullifier secret.
//!
//! `keys` fetches the public keys only. The first `Decrypt` returns the
//! plaintexts and the nullifier secret together. Asking for the secret before
//! any note has been opened sends one empty `Decrypt`.

use hkdf::Hkdf;
use qos_p256::encrypt::P256EncryptPublic;
use sha2::Sha256;
use spr_keypair::pubkey::PublicKey;
use spr_keypair::x25519::X25519Pubkey;
use spr_keypair::ShieldedAddress;
use spr_tvc_protocol::body_limit::encrypted_request_http_len;
use spr_tvc_protocol::constants::{API_VERSION, QOS_P256_PUBLIC_LEN};
use spr_tvc_protocol::decryption_service::{
    decrypt_message, service_request_digest, DecryptedOutputs, ServiceOperation, ServiceRequest,
    ServiceResult, ADDRESS_LEN,
};
use spr_tvc_protocol::digest::result_digest;
use spr_tvc_protocol::encoding::{is_rfc8785, jcs_serialize};
use spr_tvc_protocol::error::{ErrorCode, TvcError};
use spr_tvc_protocol::types::{
    AppProof, DecryptItem, EncryptedRequest, EncryptedResponse, KdfMode, OperationKind,
    OperationProofPayload,
};
use zeroize::{Zeroize, Zeroizing};

use crate::session::{
    decrypt_response, ensure_operation, response_keypair, verify_app_signature, Session,
};
use crate::transport::Transport;
use crate::{BootProofs, ClientError, OwnerSigner};

const TX_KEY_LABEL: &[u8] = b"TSPP/decryption-service/tx_key/v1";
const RESPONSE_ENVELOPE_SLACK: u64 = 65_536;

/// One note the service can open.
#[derive(Debug, Clone)]
pub struct Note {
    pub ciphertext: Vec<u8>,
    pub ephemeral_viewing_public_key: [u8; 33],
    pub salt: Vec<u8>,
    pub slot_index: u64,
    pub label: spr_tvc_protocol::DecryptLabel,
}

pub struct DecryptionClient<T, B> {
    session: Session<B>,
    transport: T,
}

impl<T: Transport, B: BootProofs> DecryptionClient<T, B> {
    pub(crate) fn new(session: Session<B>, transport: T) -> Self {
        Self { session, transport }
    }

    /// The shielded address a sender pays `owner` at before that owner registers.
    pub fn address(&self, owner: &[u8; ADDRESS_LEN]) -> Result<ShieldedAddress, ClientError> {
        ensure_operation(self.session.info(), OperationKind::ServicePublicKeys)?;
        let result = self.call(
            ServiceOperation::PublicKeys {
                address: bs58::encode(owner).into_string(),
            },
            None,
            owner,
        )?;
        let ServiceResult::PublicKeys {
            viewing_public_key,
            nullifier_public_key,
        } = result
        else {
            return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch).into());
        };
        Ok(ShieldedAddress {
            signing_pubkey: PublicKey::from_ed25519(owner),
            nullifier_pubkey: nullifier_public_key,
            viewing_pubkey: X25519Pubkey::from_bytes(viewing_public_key)
                .map_err(|_| TvcError::new(ErrorCode::InvalidPublicKey))?,
        })
    }

    /// Keys for `signer`. Does not call `Decrypt`.
    pub fn keys<'a>(
        &'a self,
        signer: &'a dyn OwnerSigner,
    ) -> Result<ServiceKeys<'a, T, B>, ClientError> {
        let owner = signer.pubkey();
        let address = self.address(&owner)?;
        Ok(ServiceKeys {
            client: self,
            signer,
            address,
            secret: None,
        })
    }

    fn call(
        &self,
        operation: ServiceOperation,
        signer: Option<&dyn OwnerSigner>,
        owner: &[u8; ADDRESS_LEN],
    ) -> Result<ServiceResult, ClientError> {
        self.session.require_current()?;
        let (pair, public) = response_keypair();
        let mut request = ServiceRequest {
            version: API_VERSION,
            request_id: random_32()?,
            target_release_id: self.session.info().release_id.clone(),
            target_manifest_digest: self.session.info().manifest_digest,
            target_executable_digest: self.session.info().executable_digest,
            quorum_key_id: self.session.info().quorum_key_id.clone(),
            quorum_key_epoch: self.session.info().quorum_key_epoch,
            client_response_public_key: public,
            operation,
        };
        let digest = service_request_digest(&request)?;
        // A Decrypt signature is fixed at 64 bytes, so this length is the signed length.
        let inner_len = jcs_serialize(&request)?.len();
        let http_len = encrypted_request_http_len(
            inner_len,
            &request.quorum_key_id,
            request.quorum_key_epoch,
        )?;
        if http_len as u64 > self.session.info().max_encrypted_request_bytes {
            return Err(TvcError::new(ErrorCode::RequestTooLarge).into());
        }
        if let Some(signer) = signer {
            if signer.pubkey() != *owner {
                return Err(TvcError::new(ErrorCode::InvalidSignature).into());
            }
            let message = decrypt_message(owner, self.session.info().network, &digest);
            let signature = signer.sign_offchain(&message)?;
            if let ServiceOperation::Decrypt {
                signature: slot, ..
            } = &mut request.operation
            {
                *slot = signature;
            }
        }
        let inner = jcs_serialize(&request)?;
        self.session.require_current()?;
        let quorum = quorum_encryption_key(&self.session.info().quorum_public_key)?;
        let ciphertext = quorum
            .encrypt(inner.as_bytes())
            .map_err(|_| TvcError::new(ErrorCode::InvalidPublicKey))?;
        let wire = jcs_serialize(&EncryptedRequest {
            version: API_VERSION,
            quorum_key_id: request.quorum_key_id.clone(),
            quorum_key_epoch: request.quorum_key_epoch,
            ciphertext,
        })?;
        if wire.len() as u64 > self.session.info().max_encrypted_request_bytes {
            return Err(TvcError::new(ErrorCode::RequestTooLarge).into());
        }
        let max_response = self
            .session
            .info()
            .max_encrypted_response_bytes
            .saturating_mul(2)
            .saturating_add(RESPONSE_ENVELOPE_SLACK);
        let limit = usize::try_from(max_response).map_err(|_| ClientError::ResponseTooLarge)?;
        let body = self.transport.post(
            &format!(
                "{}/v1/operations",
                self.session.endpoint().trim_end_matches('/')
            ),
            &wire,
            limit,
        )?;
        let text = std::str::from_utf8(&body)
            .map_err(|_| TvcError::new(ErrorCode::InvalidCanonicalJson))?;
        if !is_rfc8785(text) {
            return Err(TvcError::new(ErrorCode::InvalidCanonicalJson).into());
        }
        let response: EncryptedResponse = spr_tvc_protocol::encoding::parse_strict_json(text)?;
        if response.version != API_VERSION || response.request_id != request.request_id {
            return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch).into());
        }
        if response.encrypted_result.len() as u64 > self.session.info().max_encrypted_response_bytes
        {
            return Err(ClientError::ResponseTooLarge);
        }
        self.verify_operation(
            &response.tvc_app_proof,
            &digest,
            &response.encrypted_result,
            &request,
        )?;
        let plaintext = decrypt_response(&pair, &response.encrypted_result)?;
        let plaintext = std::str::from_utf8(&plaintext)
            .map_err(|_| TvcError::new(ErrorCode::InvalidCanonicalJson))?;
        if !is_rfc8785(plaintext) {
            return Err(TvcError::new(ErrorCode::InvalidCanonicalJson).into());
        }
        let result: ServiceResult = spr_tvc_protocol::encoding::parse_strict_json(plaintext)?;
        match (&request.operation, &result) {
            (ServiceOperation::PublicKeys { .. }, ServiceResult::PublicKeys { .. })
            | (ServiceOperation::Decrypt { .. }, ServiceResult::Decrypt(_)) => Ok(result),
            _ => Err(TvcError::new(ErrorCode::ReleaseBindingMismatch).into()),
        }
    }

    fn verify_operation(
        &self,
        proof: &AppProof,
        request_digest: &[u8; 32],
        encrypted_result: &[u8],
        request: &ServiceRequest,
    ) -> Result<(), ClientError> {
        verify_app_signature(proof)?;
        self.session.verify_operation_key(proof)?;
        if !is_rfc8785(&proof.proof_payload) {
            return Err(TvcError::new(ErrorCode::TurnkeyEvidenceInvalid).into());
        }
        let payload: OperationProofPayload =
            spr_tvc_protocol::encoding::parse_strict_json(&proof.proof_payload)?;
        if payload.r#type != spr_tvc_protocol::decryption_service::SERVICE_PROOF_TYPE
            || payload.version != API_VERSION
            || payload.request_id != request.request_id
            || payload.request_digest != *request_digest
            || payload.result_digest != result_digest(encrypted_result)
            || payload.operation != request.operation.kind()
        {
            return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch).into());
        }
        Ok(())
    }

    fn decrypt_items(
        &self,
        signer: &dyn OwnerSigner,
        items: Vec<DecryptItem>,
    ) -> Result<DecryptedOutputs, ClientError> {
        ensure_operation(self.session.info(), OperationKind::ServiceDecrypt)?;
        let owner = signer.pubkey();
        let result = self.call(
            ServiceOperation::Decrypt {
                signer: bs58::encode(owner).into_string(),
                signature: [0; 64],
                items,
                grant: None,
            },
            Some(signer),
            &owner,
        )?;
        match result {
            ServiceResult::Decrypt(outputs) => Ok(outputs),
            ServiceResult::PublicKeys { .. } => {
                Err(TvcError::new(ErrorCode::ReleaseBindingMismatch).into())
            }
        }
    }
}

/// Shielded keys whose notes the service opens.
pub struct ServiceKeys<'a, T, B> {
    client: &'a DecryptionClient<T, B>,
    signer: &'a dyn OwnerSigner,
    address: ShieldedAddress,
    secret: Option<Zeroizing<[u8; 31]>>,
}

impl<T: Transport, B: BootProofs> ServiceKeys<'_, T, B> {
    pub fn address(&self) -> ShieldedAddress {
        self.address
    }

    /// Opens `notes` in order. The reply also carries the nullifier secret.
    pub fn decrypt(&mut self, notes: &[Note]) -> Result<Vec<Vec<u8>>, ClientError> {
        if notes.is_empty() {
            return Ok(Vec::new());
        }
        let items: Vec<DecryptItem> = notes.iter().map(note_item).collect();
        let mut outputs = self.open(items)?;
        self.store_secret(outputs.nullifier_secret);
        Ok(std::mem::take(&mut outputs.plaintexts))
    }

    /// A copy of the nullifier secret. The caller wipes it.
    ///
    /// The first note decrypt supplies it. A spend that has not opened notes fetches it once.
    pub fn nullifier_secret(&mut self) -> Result<[u8; 31], ClientError> {
        if self.secret.is_none() {
            let outputs = self.open(Vec::new())?;
            self.store_secret(outputs.nullifier_secret);
        }
        Ok(**self
            .secret
            .as_ref()
            .ok_or_else(|| TvcError::new(ErrorCode::ReleaseBindingMismatch))?)
    }

    /// HKDF seed the wallet uses for local transaction viewing keys.
    pub fn transaction_viewing_seed(&mut self) -> Result<[u8; 32], ClientError> {
        let mut secret = self.nullifier_secret()?;
        let mut seed = [0u8; 32];
        Hkdf::<Sha256>::new(None, &secret)
            .expand(TX_KEY_LABEL, &mut seed)
            .expect("32 bytes fits HKDF-SHA256");
        secret.zeroize();
        Ok(seed)
    }

    fn open(&self, items: Vec<DecryptItem>) -> Result<DecryptedOutputs, ClientError> {
        if items.len() < 2 {
            return self.client.decrypt_items(self.signer, items);
        }
        match self.client.decrypt_items(self.signer, items.clone()) {
            Err(ClientError::Protocol(error)) if error.code == ErrorCode::RequestTooLarge => {
                let middle = items.len() / 2;
                let mut left = self.open(items[..middle].to_vec())?;
                let mut right = self.open(items[middle..].to_vec())?;
                left.plaintexts.append(&mut right.plaintexts);
                right.nullifier_secret.zeroize();
                Ok(left)
            }
            other => other,
        }
    }

    fn store_secret(&mut self, mut secret: [u8; 31]) {
        if self.secret.is_some() {
            secret.zeroize();
            return;
        }
        self.secret = Some(Zeroizing::new(secret));
        secret.zeroize();
    }
}

fn note_item(note: &Note) -> DecryptItem {
    DecryptItem {
        ciphertext: note.ciphertext.clone(),
        ephemeral_viewing_public_key: note.ephemeral_viewing_public_key.to_vec(),
        salt: note.salt.clone(),
        slot_index: note.slot_index,
        label: note.label,
        kdf: KdfMode::HkdfSha256Ctr,
    }
}

fn quorum_encryption_key(public_key: &[u8]) -> Result<P256EncryptPublic, TvcError> {
    if public_key.len() != QOS_P256_PUBLIC_LEN {
        return Err(TvcError::new(ErrorCode::InvalidPublicKey));
    }
    P256EncryptPublic::from_bytes(&public_key[..65])
        .map_err(|_| TvcError::new(ErrorCode::InvalidPublicKey))
}

fn random_32() -> Result<[u8; 32], ClientError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| ClientError::Entropy)?;
    Ok(bytes)
}
