//! `keys` and `decrypt` go to `POST /v1/decryption/operations`. The request
//! names the Quorum key in the signed pin. Each reply carries the Boot Proof of
//! the replica that signed it, checked with the App Proof before the result opens.

use crate::attestation::{now_ms, BootProof, IdentityPcrs};
use crate::service::{
    bind_operation_proof, decrypt_operation, shielded_address, CheckReply, Exchange, OpenNotes,
    ServiceKeys, Target, RESPONSE_ENVELOPE_SLACK,
};
use crate::session::{join, verify_connection_release, verify_reply_boot, Session};
use crate::transport::Transport;
use crate::{ClientError, OwnerSigner};
use base64::Engine;
use serde::Deserialize;
use spr_keypair::ShieldedAddress;
use spr_tvc_wire::constants::QOS_P256_PUBLIC_LEN;
use spr_tvc_wire::decryption_service::{
    DecryptedOutputs, ServiceOperation, ServiceRequest, ADDRESS_LEN,
};
use spr_tvc_wire::encoding::{decode_lower_hex, parse_strict_json};
use spr_tvc_wire::error::{ErrorCode, TvcError};
use spr_tvc_wire::release::PinnedReleaseAuthorities;
use spr_tvc_wire::types::{
    AppProof, DecryptItem, EncryptedResponse, Network, OperationKind, SignedReleasePolicy,
};

const BOOT_PROOF_SLACK: u64 = 512 * 1024;

/// HTTPS origin and the API key sent as `x-api-key`.
pub struct OperationsConfig {
    pub endpoint: String,
    pub api_key: String,
}

/// `keys` and `decrypt` at an HTTPS origin. Each reply's Boot Proof is checked.
pub struct OperationsClient<T> {
    session: Session<()>,
    transport: T,
    api_key: String,
}

impl<T: Transport> OperationsClient<T> {
    pub fn connect(
        network: Network,
        config: OperationsConfig,
        release: SignedReleasePolicy,
        authorities: PinnedReleaseAuthorities,
        pcrs: IdentityPcrs,
        transport: T,
    ) -> Result<Self, ClientError> {
        require_https_origin(&config.endpoint, &config.api_key)?;
        let now = now_ms;
        verify_connection_release(network, &release, &authorities, &pcrs, now())?;
        Ok(Self {
            session: Session::verified(config.endpoint, release, pcrs, now),
            transport,
            api_key: config.api_key,
        })
    }

    /// The shielded address a sender pays `owner` at before that owner registers.
    pub fn address(&self, owner: &[u8; ADDRESS_LEN]) -> Result<ShieldedAddress, ClientError> {
        crate::session::ensure_operation(
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
        grant: &'a spr_tvc_wire::decryption_service::ViewGrant,
    ) -> Result<ServiceKeys<'a>, ClientError> {
        let owner = crate::service::grant_owner(
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
    ) -> Result<spr_tvc_wire::decryption_service::ServiceResult, ClientError> {
        Exchange {
            target: Target::from_policy(&self.session.release().policy),
            operation,
            signer,
            owner,
            checker: self,
        }
        .run()
    }
}

impl<T: Transport> CheckReply for OperationsClient<T> {
    fn gate(&self) -> Result<(), TvcError> {
        self.session.require_current()
    }

    fn response_overhead(&self) -> u64 {
        RESPONSE_ENVELOPE_SLACK + BOOT_PROOF_SLACK
    }

    fn post_operation(&self, body: &str, limit: usize) -> Result<Vec<u8>, ClientError> {
        self.transport.post_with_api_key(
            &join(self.session.endpoint(), "/v1/decryption/operations"),
            &self.api_key,
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
        let answer: OperationAnswer = parse_strict_json(text)?;
        let boot = decode_boot_proof(&answer.boot_proof)?;
        Ok((answer.response, Some(boot)))
    }

    fn check_reply(
        &self,
        proof: &AppProof,
        request_digest: &[u8; 32],
        encrypted_result: &[u8],
        request: &ServiceRequest,
        boot: Option<&BootProof>,
    ) -> Result<(), ClientError> {
        let boot = boot.ok_or_else(|| TvcError::boot("decode"))?;
        verify_reply_boot(
            self.session.release(),
            self.session.pcrs(),
            proof,
            boot,
            self.session.now_ms(),
        )?;
        bind_operation_proof(proof, request_digest, encrypted_result, request)
    }
}

impl<T: Transport> OpenNotes for OperationsClient<T> {
    fn decrypt_items(
        &self,
        signer: &dyn OwnerSigner,
        items: Vec<DecryptItem>,
        grant: Option<&spr_tvc_wire::decryption_service::ViewGrant>,
    ) -> Result<DecryptedOutputs, ClientError> {
        crate::session::ensure_operation(
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
            spr_tvc_wire::decryption_service::ServiceResult::Decrypt(outputs) => Ok(outputs),
            spr_tvc_wire::decryption_service::ServiceResult::PublicKeys { .. } => {
                Err(TvcError::new(ErrorCode::ReleaseBindingMismatch).into())
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireBootProof {
    aws_attestation_doc_b64: String,
    ephemeral_public_key_hex: String,
    #[serde(default)]
    qos_manifest_envelope_b64: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OperationAnswer {
    response: EncryptedResponse,
    boot_proof: WireBootProof,
}

fn decode_boot_proof(wire: &WireBootProof) -> Result<BootProof, TvcError> {
    let attestation = base64::engine::general_purpose::STANDARD
        .decode(wire.aws_attestation_doc_b64.as_bytes())
        .map_err(|_| TvcError::boot("decode"))?;
    let key =
        decode_lower_hex(&wire.ephemeral_public_key_hex).map_err(|_| TvcError::boot("decode"))?;
    if key.len() != QOS_P256_PUBLIC_LEN {
        return Err(TvcError::boot("decode"));
    }
    let mut ephemeral_public_key = [0u8; QOS_P256_PUBLIC_LEN];
    ephemeral_public_key.copy_from_slice(&key);
    let manifest_envelope = base64::engine::general_purpose::STANDARD
        .decode(wire.qos_manifest_envelope_b64.as_bytes())
        .map_err(|_| TvcError::boot("decode"))?;
    Ok(BootProof {
        attestation,
        ephemeral_public_key,
        manifest_envelope,
    })
}

fn require_https_origin(endpoint: &str, api_key: &str) -> Result<(), ClientError> {
    let url = reqwest::Url::parse(endpoint).map_err(|_| ClientError::InvalidServiceConfig)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.path() != "/" && !url.path().is_empty())
        || api_key.trim().is_empty()
        || reqwest::header::HeaderValue::from_str(api_key).is_err()
    {
        return Err(ClientError::InvalidServiceConfig);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/operations.rs"]
mod tests;
