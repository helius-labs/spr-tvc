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
    AppProof, DecryptItem, EncryptedRequest, EncryptedResponse, KdfMode, Network, OperationKind,
    OperationProofPayload, ServiceInfo,
};
use zeroize::{Zeroize, Zeroizing};

use crate::attestation::BootProof;
use crate::session::{
    decrypt_response, ensure_operation, response_keypair, verify_app_signature, Session,
};
use crate::transport::Transport;
use crate::{BootProofs, ClientError, OwnerSigner};

const TX_KEY_LABEL: &[u8] = b"TSPP/decryption-service/tx_key/v1";
pub(crate) const RESPONSE_ENVELOPE_SLACK: u64 = 65_536;

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
        shielded_address(owner, result)
    }

    /// Keys for `signer`. Does not call `Decrypt`.
    pub fn keys<'a>(&'a self, signer: &'a dyn OwnerSigner) -> Result<ServiceKeys<'a>, ClientError> {
        let owner = signer.pubkey();
        let address = self.address(&owner)?;
        Ok(ServiceKeys::new(self, signer, address))
    }

    fn call(
        &self,
        operation: ServiceOperation,
        signer: Option<&dyn OwnerSigner>,
        owner: &[u8; ADDRESS_LEN],
    ) -> Result<ServiceResult, ClientError> {
        let info = self.session.info();
        Exchange {
            target: Target::from_info(info),
            operation,
            signer,
            owner,
            checker: self,
        }
        .run()
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

pub(crate) trait OpenNotes {
    fn decrypt_items(
        &self,
        signer: &dyn OwnerSigner,
        items: Vec<DecryptItem>,
    ) -> Result<DecryptedOutputs, ClientError>;
}

impl<T: Transport, B: BootProofs> CheckReply for DecryptionClient<T, B> {
    fn gate(&self) -> Result<(), TvcError> {
        self.session.require_current()
    }

    fn post_operation(&self, body: &str, limit: usize) -> Result<Vec<u8>, ClientError> {
        self.transport.post(
            &format!(
                "{}/v1/operations",
                self.session.endpoint().trim_end_matches('/')
            ),
            body,
            limit,
        )
    }

    fn open_http(
        &self,
        body: &[u8],
    ) -> Result<(EncryptedResponse, Option<BootProof>), ClientError> {
        let text = std::str::from_utf8(body)
            .map_err(|_| TvcError::new(ErrorCode::InvalidCanonicalJson))?;
        if !is_rfc8785(text) {
            return Err(TvcError::new(ErrorCode::InvalidCanonicalJson).into());
        }
        let response = spr_tvc_protocol::encoding::parse_strict_json(text)?;
        Ok((response, None))
    }

    fn check_reply(
        &self,
        proof: &AppProof,
        request_digest: &[u8; 32],
        encrypted_result: &[u8],
        request: &ServiceRequest,
        _: Option<&BootProof>,
    ) -> Result<(), ClientError> {
        verify_app_signature(proof)?;
        self.session.verify_operation_key(proof)?;
        bind_operation_proof(proof, request_digest, encrypted_result, request)
    }
}

impl<T: Transport, B: BootProofs> OpenNotes for DecryptionClient<T, B> {
    fn decrypt_items(
        &self,
        signer: &dyn OwnerSigner,
        items: Vec<DecryptItem>,
    ) -> Result<DecryptedOutputs, ClientError> {
        DecryptionClient::decrypt_items(self, signer, items)
    }
}

/// Shielded keys whose notes the service opens.
pub struct ServiceKeys<'a> {
    opener: &'a dyn OpenNotes,
    signer: &'a dyn OwnerSigner,
    address: ShieldedAddress,
    secret: Option<Zeroizing<[u8; 31]>>,
}

impl<'a> ServiceKeys<'a> {
    pub(crate) fn new(
        opener: &'a dyn OpenNotes,
        signer: &'a dyn OwnerSigner,
        address: ShieldedAddress,
    ) -> Self {
        Self {
            opener,
            signer,
            address,
            secret: None,
        }
    }
}

impl ServiceKeys<'_> {
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
            return self.opener.decrypt_items(self.signer, items);
        }
        match self.opener.decrypt_items(self.signer, items.clone()) {
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

pub(crate) struct Target<'a> {
    pub(crate) network: Network,
    pub(crate) release_id: &'a str,
    pub(crate) manifest_digest: [u8; 32],
    pub(crate) executable_digest: [u8; 32],
    pub(crate) quorum_key_id: &'a str,
    pub(crate) quorum_key_epoch: u64,
    pub(crate) quorum_public_key: &'a [u8],
    pub(crate) max_request: u64,
    pub(crate) max_response: u64,
}

impl<'a> Target<'a> {
    pub(crate) fn from_info(info: &'a ServiceInfo) -> Self {
        Self {
            network: info.network,
            release_id: &info.release_id,
            manifest_digest: info.manifest_digest,
            executable_digest: info.executable_digest,
            quorum_key_id: &info.quorum_key_id,
            quorum_key_epoch: info.quorum_key_epoch,
            quorum_public_key: &info.quorum_public_key,
            max_request: info.max_encrypted_request_bytes,
            max_response: info.max_encrypted_response_bytes,
        }
    }
}

pub(crate) trait CheckReply {
    fn gate(&self) -> Result<(), TvcError>;
    fn response_overhead(&self) -> u64 {
        RESPONSE_ENVELOPE_SLACK
    }
    fn post_operation(&self, body: &str, limit: usize) -> Result<Vec<u8>, ClientError>;
    fn open_http(&self, body: &[u8])
        -> Result<(EncryptedResponse, Option<BootProof>), ClientError>;
    fn check_reply(
        &self,
        proof: &AppProof,
        request_digest: &[u8; 32],
        encrypted_result: &[u8],
        request: &ServiceRequest,
        boot: Option<&BootProof>,
    ) -> Result<(), ClientError>;
}

pub(crate) fn bind_operation_proof(
    proof: &AppProof,
    request_digest: &[u8; 32],
    encrypted_result: &[u8],
    request: &ServiceRequest,
) -> Result<(), ClientError> {
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

pub(crate) struct Exchange<'a> {
    pub(crate) target: Target<'a>,
    pub(crate) operation: ServiceOperation,
    pub(crate) signer: Option<&'a dyn OwnerSigner>,
    pub(crate) owner: &'a [u8; ADDRESS_LEN],
    pub(crate) checker: &'a dyn CheckReply,
}

impl Exchange<'_> {
    pub(crate) fn run(self) -> Result<ServiceResult, ClientError> {
        let Exchange {
            target,
            operation,
            signer,
            owner,
            checker,
        } = self;
        checker.gate()?;
        let (pair, public) = response_keypair();
        let mut request = ServiceRequest {
            version: API_VERSION,
            request_id: random_32()?,
            target_release_id: target.release_id.to_owned(),
            target_manifest_digest: target.manifest_digest,
            target_executable_digest: target.executable_digest,
            quorum_key_id: target.quorum_key_id.to_owned(),
            quorum_key_epoch: target.quorum_key_epoch,
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
        if http_len as u64 > target.max_request {
            return Err(TvcError::new(ErrorCode::RequestTooLarge).into());
        }
        if let Some(signer) = signer {
            if signer.pubkey() != *owner {
                return Err(TvcError::new(ErrorCode::InvalidSignature).into());
            }
            let message = decrypt_message(owner, target.network, &digest);
            let signature = signer.sign_offchain(&message)?;
            if let ServiceOperation::Decrypt {
                signature: slot, ..
            } = &mut request.operation
            {
                *slot = signature;
            }
        }
        let inner = jcs_serialize(&request)?;
        checker.gate()?;
        let quorum = quorum_encryption_key(target.quorum_public_key)?;
        let ciphertext = quorum
            .encrypt(inner.as_bytes())
            .map_err(|_| TvcError::new(ErrorCode::InvalidPublicKey))?;
        let wire = jcs_serialize(&EncryptedRequest {
            version: API_VERSION,
            quorum_key_id: request.quorum_key_id.clone(),
            quorum_key_epoch: request.quorum_key_epoch,
            ciphertext,
        })?;
        if wire.len() as u64 > target.max_request {
            return Err(TvcError::new(ErrorCode::RequestTooLarge).into());
        }
        let max_response = target
            .max_response
            .saturating_mul(2)
            .saturating_add(checker.response_overhead());
        let limit = usize::try_from(max_response).map_err(|_| ClientError::ResponseTooLarge)?;
        let body = checker.post_operation(&wire, limit)?;
        let (response, boot) = checker.open_http(&body)?;
        if response.version != API_VERSION || response.request_id != request.request_id {
            return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch).into());
        }
        if response.encrypted_result.len() as u64 > target.max_response {
            return Err(ClientError::ResponseTooLarge);
        }
        checker.check_reply(
            &response.tvc_app_proof,
            &digest,
            &response.encrypted_result,
            &request,
            boot.as_ref(),
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
}

pub(crate) fn shielded_address(
    owner: &[u8; ADDRESS_LEN],
    result: ServiceResult,
) -> Result<ShieldedAddress, ClientError> {
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
