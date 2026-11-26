//! Public keys, note decryption, and the nullifier secret.
//!
//! `keys` fetches the public keys only. The first `Decrypt` returns the
//! plaintexts and the nullifier secret together. Asking for the secret before
//! any note has been opened sends one empty `Decrypt`.
//! [`SignViewGrant`] is the owner's signature that lets a grantee call `keys_for`.

use hkdf::Hkdf;
use qos_p256::encrypt::P256EncryptPublic;
use sha2::Sha256;
use spr_keypair::pubkey::PublicKey;
use spr_keypair::x25519::X25519Pubkey;
use spr_keypair::ShieldedAddress;
use spr_tvc_wire::body_limit::encrypted_request_http_len;
use spr_tvc_wire::constants::{API_VERSION, QOS_P256_PUBLIC_LEN};
use spr_tvc_wire::decryption_service::{
    accept_view_grant_window, decrypt_message, service_request_digest, view_grant_digest,
    view_grant_message, DecryptedOutputs, ServiceOperation, ServiceRequest, ServiceResult,
    ViewGrant, ADDRESS_LEN,
};
use spr_tvc_wire::digest::result_digest;
use spr_tvc_wire::encoding::{is_rfc8785, jcs_serialize};
use spr_tvc_wire::error::{ErrorCode, TvcError};
use spr_tvc_wire::types::{
    AppProof, DecryptItem, EncryptedRequest, EncryptedResponse, KdfMode, Network, OperationKind,
    OperationProofPayload, ReleasePolicy,
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
    pub label: spr_tvc_wire::DecryptLabel,
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
        ensure_operation(
            &self.session.release().policy,
            OperationKind::ServicePublicKeys,
        )?;
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
        Ok(ServiceKeys::new(self, signer, address, None))
    }

    /// Keys for the grant's owner. `grantee` signs each later `Decrypt`.
    pub fn keys_for<'a>(
        &'a self,
        grantee: &'a dyn OwnerSigner,
        grant: &'a ViewGrant,
    ) -> Result<ServiceKeys<'a>, ClientError> {
        let owner = grant_owner(
            grantee,
            grant,
            &self.session.release().policy,
            self.session.now_ms(),
        )?;
        let address = self.address(&owner)?;
        Ok(ServiceKeys::new(self, grantee, address, Some(grant)))
    }

    fn call(
        &self,
        operation: ServiceOperation,
        signer: Option<&dyn OwnerSigner>,
        owner: &[u8; ADDRESS_LEN],
    ) -> Result<ServiceResult, ClientError> {
        Exchange {
            target: Target::from_policy(&self.session.release().policy),
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
        grant: Option<&ViewGrant>,
    ) -> Result<DecryptedOutputs, ClientError> {
        ensure_operation(
            &self.session.release().policy,
            OperationKind::ServiceDecrypt,
        )?;
        let owner = signer.pubkey();
        let result = self.call(
            decrypt_operation(
                signer,
                items,
                grant,
                &self.session.release().policy,
                self.session.now_ms(),
            )?,
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
        grant: Option<&ViewGrant>,
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
        let response = spr_tvc_wire::encoding::parse_strict_json(text)?;
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
        grant: Option<&ViewGrant>,
    ) -> Result<DecryptedOutputs, ClientError> {
        DecryptionClient::decrypt_items(self, signer, items, grant)
    }
}

/// Shielded keys whose notes the service opens.
pub struct ServiceKeys<'a> {
    opener: &'a dyn OpenNotes,
    signer: &'a dyn OwnerSigner,
    address: ShieldedAddress,
    grant: Option<&'a ViewGrant>,
    secret: Option<Zeroizing<[u8; 31]>>,
}

impl<'a> ServiceKeys<'a> {
    pub(crate) fn new(
        opener: &'a dyn OpenNotes,
        signer: &'a dyn OwnerSigner,
        address: ShieldedAddress,
        grant: Option<&'a ViewGrant>,
    ) -> Self {
        Self {
            opener,
            signer,
            address,
            grant,
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
            return self.opener.decrypt_items(self.signer, items, self.grant);
        }
        match self
            .opener
            .decrypt_items(self.signer, items.clone(), self.grant)
        {
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

/// The owner signs this for `grantee`. The window is at most 30 minutes.
pub struct SignViewGrant<'a> {
    pub grantee: [u8; ADDRESS_LEN],
    pub network: Network,
    pub quorum_key_id: &'a str,
    pub quorum_key_epoch: u64,
    pub not_before_ms: u64,
    pub expiry_ms: u64,
}

impl SignViewGrant<'_> {
    pub fn sign(self, owner: &dyn OwnerSigner) -> Result<ViewGrant, ClientError> {
        accept_view_grant_window(self.not_before_ms, self.expiry_ms, self.not_before_ms)?;
        if self.grantee == owner.pubkey() {
            return Err(TvcError::new(ErrorCode::InvalidSignature).into());
        }
        let mut grant = ViewGrant {
            owner: bs58::encode(owner.pubkey()).into_string(),
            grantee: bs58::encode(self.grantee).into_string(),
            network: self.network,
            quorum_key_id: self.quorum_key_id.to_owned(),
            quorum_key_epoch: self.quorum_key_epoch,
            not_before_ms: self.not_before_ms,
            expiry_ms: self.expiry_ms,
            signature: [0; 64],
        };
        let digest = view_grant_digest(&grant)?;
        grant.signature = owner.sign_offchain(&view_grant_message(&owner.pubkey(), &digest))?;
        Ok(grant)
    }
}

pub(crate) fn decrypt_operation(
    signer: &dyn OwnerSigner,
    items: Vec<DecryptItem>,
    grant: Option<&ViewGrant>,
    policy: &ReleasePolicy,
    now_ms: u64,
) -> Result<ServiceOperation, ClientError> {
    if let Some(grant) = grant {
        grant_owner(signer, grant, policy, now_ms)?;
    }
    Ok(ServiceOperation::Decrypt {
        signer: bs58::encode(signer.pubkey()).into_string(),
        signature: [0; 64],
        items,
        grant: grant.cloned().map(Box::new),
    })
}

pub(crate) fn grant_owner(
    grantee: &dyn OwnerSigner,
    grant: &ViewGrant,
    policy: &ReleasePolicy,
    now_ms: u64,
) -> Result<[u8; ADDRESS_LEN], ClientError> {
    let grantee_key = address_bytes(&grant.grantee)?;
    let owner = address_bytes(&grant.owner)?;
    if grantee_key != grantee.pubkey()
        || owner == grantee_key
        || grant.network != policy.network
        || grant.quorum_key_id != policy.quorum_key_id
        || grant.quorum_key_epoch != policy.quorum_key_epoch
    {
        return Err(TvcError::new(ErrorCode::InvalidSignature).into());
    }
    accept_view_grant_window(grant.not_before_ms, grant.expiry_ms, now_ms)?;
    Ok(owner)
}

fn address_bytes(address: &str) -> Result<[u8; ADDRESS_LEN], ClientError> {
    let bytes = bs58::decode(address)
        .into_vec()
        .map_err(|_| TvcError::new(ErrorCode::InvalidSignature))?;
    bytes
        .try_into()
        .map_err(|_| TvcError::new(ErrorCode::InvalidSignature).into())
}

pub(crate) struct Target<'a> {
    pub(crate) network: Network,
    pub(crate) quorum_key_id: &'a str,
    pub(crate) quorum_key_epoch: u64,
    pub(crate) quorum_public_key: &'a [u8],
    pub(crate) max_request: u64,
    pub(crate) max_response: u64,
}

impl<'a> Target<'a> {
    pub(crate) fn from_policy(policy: &'a ReleasePolicy) -> Self {
        Self {
            network: policy.network,
            quorum_key_id: &policy.quorum_key_id,
            quorum_key_epoch: policy.quorum_key_epoch,
            quorum_public_key: &policy.quorum_public_key,
            max_request: u64::from(policy.max_encrypted_request_bytes),
            max_response: u64::from(policy.max_encrypted_response_bytes),
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
        spr_tvc_wire::encoding::parse_strict_json(&proof.proof_payload)?;
    if payload.r#type != spr_tvc_wire::decryption_service::SERVICE_PROOF_TYPE
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
        let result: ServiceResult = spr_tvc_wire::encoding::parse_strict_json(plaintext)?;
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

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signer;
    use spr_tvc_wire::constants::API_VERSION;
    use spr_tvc_wire::decryption_service::{
        view_grant_digest, view_grant_message, MAX_VIEW_GRANT_MS,
    };
    use spr_tvc_wire::error::ErrorCode;
    use spr_tvc_wire::types::{ManifestSetPolicy, Network, ReleasePolicy};

    use super::*;

    struct Key(ed25519_dalek::SigningKey);

    impl Key {
        fn from_seed(seed: u8) -> Self {
            Self(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
        }
    }

    impl OwnerSigner for Key {
        fn pubkey(&self) -> [u8; 32] {
            self.0.verifying_key().to_bytes()
        }

        fn sign_offchain(&self, message: &[u8]) -> Result<[u8; 64], ClientError> {
            Ok(self.0.sign(message).to_bytes())
        }
    }

    fn policy() -> ReleasePolicy {
        ReleasePolicy {
            version: API_VERSION,
            network: Network::Devnet,
            security_domain_id: [0; 32],
            namespace: "namespace".into(),
            manifest_set: ManifestSetPolicy {
                threshold: 1,
                members: Vec::new(),
            },
            minimum_manifest_nonce: 0,
            quorum_key_id: "quorum".into(),
            quorum_key_epoch: 1,
            quorum_public_key: Vec::new(),
            allowed_operations: Vec::new(),
            max_encrypted_request_bytes: 1,
            max_encrypted_response_bytes: 1,
            turnkey_trust_root_id: "root".into(),
            valid_from_ms: 0,
            expires_at_ms: 1,
            revocation_epoch: 0,
        }
    }

    fn grant_for(grantee: &Key, not_before_ms: u64, expiry_ms: u64) -> SignViewGrant<'static> {
        SignViewGrant {
            grantee: grantee.pubkey(),
            network: Network::Devnet,
            quorum_key_id: "quorum",
            quorum_key_epoch: 1,
            not_before_ms,
            expiry_ms,
        }
    }

    fn code(error: ClientError) -> ErrorCode {
        match error {
            ClientError::Protocol(error) => error.code,
            other => panic!("protocol error, got {other}"),
        }
    }

    #[test]
    fn the_owner_signs_the_grant_and_the_grantee_carries_it() {
        let owner = Key::from_seed(1);
        let grantee = Key::from_seed(2);
        let grant = grant_for(&grantee, 1_000, 1_000 + MAX_VIEW_GRANT_MS)
            .sign(&owner)
            .expect("grant");
        let digest = view_grant_digest(&grant).expect("digest");
        owner
            .0
            .verifying_key()
            .verify_strict(
                &view_grant_message(&owner.pubkey(), &digest),
                &ed25519_dalek::Signature::from_bytes(&grant.signature),
            )
            .expect("owner signature");

        let operation = decrypt_operation(&grantee, Vec::new(), Some(&grant), &policy(), 1_000)
            .expect("decrypt");
        let ServiceOperation::Decrypt {
            signer,
            grant: carried,
            ..
        } = operation
        else {
            panic!("decrypt operation");
        };
        assert_eq!(signer, bs58::encode(grantee.pubkey()).into_string());
        assert_eq!(
            carried.expect("grant").owner,
            bs58::encode(owner.pubkey()).into_string()
        );

        let other = Key::from_seed(3);
        assert_eq!(
            code(grant_owner(&other, &grant, &policy(), 1_000).expect_err("grantee")),
            ErrorCode::InvalidSignature
        );
        assert_eq!(
            code(
                grant_owner(&grantee, &grant, &policy(), 1_000 + MAX_VIEW_GRANT_MS)
                    .expect_err("expired")
            ),
            ErrorCode::ExpiredRequest
        );

        let mut other_network = grant.clone();
        other_network.network = Network::Mainnet;
        assert_eq!(
            code(grant_owner(&grantee, &other_network, &policy(), 1_000).expect_err("network")),
            ErrorCode::InvalidSignature
        );
    }

    #[test]
    fn a_grant_names_someone_else_for_at_most_thirty_minutes() {
        let owner = Key::from_seed(1);
        assert_eq!(
            code(
                grant_for(&owner, 1_000, 1_000 + 1)
                    .sign(&owner)
                    .expect_err("self")
            ),
            ErrorCode::InvalidSignature
        );
        assert_eq!(
            code(
                grant_for(&Key::from_seed(2), 1_000, 1_000 + MAX_VIEW_GRANT_MS + 1)
                    .sign(&owner)
                    .expect_err("span")
            ),
            ErrorCode::ExpiredRequest
        );
    }
}
