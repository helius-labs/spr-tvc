//! Verify one replica, then check every later reply against the same release.

use qos_p256::encrypt::{P256EncryptPair, P256EncryptPublic};
use spr_tvc_protocol::constants::{
    API_VERSION, QOS_P256_PUBLIC_LEN, TVC_APP_PROOF_SCHEME, TVC_QOS_PING_PROOF_TYPE,
};
use spr_tvc_protocol::crypto::verify_p256_message;
use spr_tvc_protocol::decryption_service::SERVICE_PROOF_TYPE;
use spr_tvc_protocol::encoding::{decode_lower_hex_array, is_rfc8785, jcs_serialize};
use spr_tvc_protocol::error::{ErrorCode, TvcError};
use spr_tvc_protocol::release::{verify_signed_release_policy, PinnedReleaseAuthorities};
use spr_tvc_protocol::types::{
    AppProof, Network, OperationKind, QosPingChallenge, QosPingRequest, QosPingResponse,
    ServiceInfo, SignedReleasePolicy,
};
use zeroize::Zeroizing;

use crate::attestation::{now_ms, verify_boot_proof, BootProof, IdentityPcrs};
use crate::transport::{discovery_limit, Transport};
use crate::ClientError;

/// Fetches the Boot Proof for the replica ephemeral key that signed a reply.
pub trait BootProofs {
    fn boot_proof(
        &self,
        ephemeral_public_key: &[u8; QOS_P256_PUBLIC_LEN],
    ) -> Result<BootProof, ClientError>;
}

impl BootProofs for () {
    fn boot_proof(&self, _: &[u8; QOS_P256_PUBLIC_LEN]) -> Result<BootProof, ClientError> {
        Err(TvcError::new(ErrorCode::BootProofUnverified).into())
    }
}

pub struct ConnectConfig<T, B> {
    pub network: Network,
    pub endpoint: String,
    pub release: SignedReleasePolicy,
    pub authorities: PinnedReleaseAuthorities,
    pub pcrs: IdentityPcrs,
    pub transport: T,
    pub boot_proofs: B,
    pub now_ms: Option<fn() -> u64>,
}

pub(crate) struct Session<B> {
    endpoint: String,
    info: ServiceInfo,
    release: SignedReleasePolicy,
    pcrs: IdentityPcrs,
    boot_proofs: B,
    now_ms: fn() -> u64,
    /// Set only by the loopback testkit. A reply must come from this key.
    expected_ephemeral: Option<[u8; QOS_P256_PUBLIC_LEN]>,
}

impl<B: BootProofs> Session<B> {
    pub(crate) fn connect<T: Transport>(
        config: ConnectConfig<T, B>,
    ) -> Result<(Self, T), ClientError> {
        let now = config.now_ms.unwrap_or(now_ms);
        verify_signed_release_policy(&config.release, &config.authorities, config.network, now())?;
        let info_bytes = config
            .transport
            .get(&join(&config.endpoint, "/v1/info"), discovery_limit())?;
        let info_text = std::str::from_utf8(&info_bytes)
            .map_err(|_| TvcError::new(ErrorCode::DiscoveryUntrusted))?;
        let info: ServiceInfo = spr_tvc_protocol::encoding::parse_strict_json(info_text)?;
        bind_discovery(&info, &config.release)?;
        let (body, payload) = ping_challenge(&info.quorum_public_key)?;
        let ping_bytes = config.transport.post(
            &join(&config.endpoint, "/v1/ping"),
            &body,
            discovery_limit(),
        )?;
        let ping_text = std::str::from_utf8(&ping_bytes)
            .map_err(|_| TvcError::new(ErrorCode::BootProofUnverified))?;
        let proof = verify_ping(ping_text, &payload)?;
        verify_key(
            &config.boot_proofs,
            &config.release,
            &config.pcrs,
            &proof,
            now(),
        )?;
        Ok((
            Self {
                endpoint: config.endpoint,
                info,
                release: config.release,
                pcrs: config.pcrs,
                boot_proofs: config.boot_proofs,
                now_ms: now,
                expected_ephemeral: None,
            },
            config.transport,
        ))
    }

    pub(crate) fn info(&self) -> &ServiceInfo {
        &self.info
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) fn now_ms(&self) -> u64 {
        (self.now_ms)()
    }

    pub(crate) fn require_current(&self) -> Result<(), TvcError> {
        let now = self.now_ms();
        if now < self.release.policy.valid_from_ms || now > self.release.policy.expires_at_ms {
            return Err(TvcError::new(ErrorCode::ExpiredRequest));
        }
        Ok(())
    }

    pub(crate) fn verify_operation_key(&self, proof: &AppProof) -> Result<(), ClientError> {
        self.require_current()?;
        if let Some(expected) = self.expected_ephemeral {
            let key = ephemeral_key(&proof.public_key)?;
            if key != expected {
                return Err(TvcError::new(ErrorCode::TurnkeyEvidenceInvalid).into());
            }
            return Ok(());
        }
        verify_key(
            &self.boot_proofs,
            &self.release,
            &self.pcrs,
            proof,
            self.now_ms(),
        )
    }

    pub(crate) fn release(&self) -> &SignedReleasePolicy {
        &self.release
    }

    pub(crate) fn pcrs(&self) -> &IdentityPcrs {
        &self.pcrs
    }
}

impl Session<()> {
    pub(crate) fn verified(
        endpoint: String,
        info: ServiceInfo,
        release: SignedReleasePolicy,
        pcrs: IdentityPcrs,
        now_ms: fn() -> u64,
    ) -> Self {
        Self {
            endpoint,
            info,
            release,
            pcrs,
            boot_proofs: (),
            now_ms,
            expected_ephemeral: None,
        }
    }

    pub(crate) fn with_loopback_key(mut self, key: [u8; QOS_P256_PUBLIC_LEN]) -> Self {
        self.expected_ephemeral = Some(key);
        self
    }
}

fn verify_key<B: BootProofs>(
    boot_proofs: &B,
    release: &SignedReleasePolicy,
    pcrs: &IdentityPcrs,
    proof: &AppProof,
    now: u64,
) -> Result<(), ClientError> {
    let key = ephemeral_key(&proof.public_key)?;
    let boot = boot_proofs.boot_proof(&key)?;
    verify_boot_proof(
        &key,
        &boot,
        &release.policy.accepted_manifest_digests,
        pcrs,
        now,
    )?;
    Ok(())
}

pub(crate) fn verify_reply_boot(
    release: &SignedReleasePolicy,
    pcrs: &IdentityPcrs,
    proof: &AppProof,
    boot: &BootProof,
    now: u64,
) -> Result<(), ClientError> {
    verify_app_signature(proof)?;
    let key = ephemeral_key(&proof.public_key)?;
    verify_boot_proof(
        &key,
        boot,
        &release.policy.accepted_manifest_digests,
        pcrs,
        now,
    )?;
    Ok(())
}

pub(crate) fn bind_discovery(
    info: &ServiceInfo,
    signed: &SignedReleasePolicy,
) -> Result<(), TvcError> {
    let policy = &signed.policy;
    if info.network != policy.network {
        return Err(TvcError::new(ErrorCode::NetworkMismatch));
    }
    if info.version != API_VERSION {
        return Err(TvcError::new(ErrorCode::UnsupportedVersion));
    }
    if info.proof_type != SERVICE_PROOF_TYPE {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    if info.release_id != policy.release_id
        || info.security_domain_id != policy.security_domain_id
        || info.quorum_key_id != policy.quorum_key_id
        || info.quorum_public_key != policy.quorum_public_key
        || !policy.accepted_manifest_digests.iter().any(|digest| {
            decode_lower_hex_array::<32>(digest).ok().as_ref() == Some(&info.manifest_digest)
        })
        || !policy.accepted_executable_digests.iter().any(|digest| {
            decode_lower_hex_array::<32>(digest).ok().as_ref() == Some(&info.executable_digest)
        })
        || info.supported_operations != policy.allowed_operations
        || info.max_encrypted_request_bytes != u64::from(policy.max_encrypted_request_bytes)
        || info.max_encrypted_response_bytes != u64::from(policy.max_encrypted_response_bytes)
    {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    if info.quorum_key_epoch != policy.quorum_key_epoch {
        return Err(TvcError::new(ErrorCode::QuorumKeyEpochMismatch));
    }
    Ok(())
}

pub(crate) fn ping_challenge(quorum_public_key: &[u8]) -> Result<(String, String), ClientError> {
    if quorum_public_key.len() != QOS_P256_PUBLIC_LEN {
        return Err(TvcError::new(ErrorCode::InvalidPublicKey).into());
    }
    let encryption = P256EncryptPublic::from_bytes(&quorum_public_key[..65])
        .map_err(|_| TvcError::new(ErrorCode::InvalidPublicKey))?;
    let mut challenge = [0u8; 32];
    getrandom::getrandom(&mut challenge).map_err(|_| ClientError::Entropy)?;
    let payload = jcs_serialize(&QosPingChallenge {
        r#type: TVC_QOS_PING_PROOF_TYPE.into(),
        version: API_VERSION,
        challenge,
    })?;
    let encrypted = encryption
        .encrypt(payload.as_bytes())
        .map_err(|_| TvcError::new(ErrorCode::InvalidPublicKey))?;
    let body = jcs_serialize(&QosPingRequest {
        version: API_VERSION,
        encrypted_challenge: encrypted,
    })?;
    Ok((body, payload))
}

pub(crate) fn verify_ping(text: &str, payload: &str) -> Result<AppProof, TvcError> {
    if !is_rfc8785(text) {
        return Err(TvcError::new(ErrorCode::InvalidCanonicalJson));
    }
    let parsed: QosPingResponse = parse_qos_ping_response(text)?;
    if parsed.version != API_VERSION
        || parsed.tvc_app_proof.scheme != TVC_APP_PROOF_SCHEME
        || parsed.tvc_app_proof.proof_payload != payload
    {
        return Err(TvcError::new(ErrorCode::TurnkeyEvidenceInvalid));
    }
    verify_app_signature(&parsed.tvc_app_proof)?;
    Ok(parsed.tvc_app_proof)
}

pub(crate) fn verify_app_signature(proof: &AppProof) -> Result<(), TvcError> {
    if proof.scheme != TVC_APP_PROOF_SCHEME || !is_rfc8785(&proof.proof_payload) {
        return Err(TvcError::new(ErrorCode::TurnkeyEvidenceInvalid));
    }
    let key = ephemeral_key(&proof.public_key)?;
    verify_p256_message(&key[65..], proof.proof_payload.as_bytes(), &proof.signature)
}

fn ephemeral_key(bytes: &[u8]) -> Result<[u8; QOS_P256_PUBLIC_LEN], TvcError> {
    bytes
        .try_into()
        .map_err(|_| TvcError::new(ErrorCode::InvalidPublicKey))
}

fn parse_qos_ping_response(text: &str) -> Result<QosPingResponse, TvcError> {
    spr_tvc_protocol::encoding::parse_strict_json(text)
}

pub(crate) fn response_keypair() -> (P256EncryptPair, Vec<u8>) {
    let pair = P256EncryptPair::generate();
    let public = pair.public_key().to_bytes().into_vec();
    (pair, public)
}

pub(crate) fn decrypt_response(
    pair: &P256EncryptPair,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, crate::ClientError> {
    pair.decrypt(envelope)
        .map_err(|_| crate::ClientError::InvalidEnvelope)
}

pub(crate) fn join(endpoint: &str, path: &str) -> String {
    format!("{}{}", endpoint.trim_end_matches('/'), path)
}

pub(crate) fn ensure_operation(info: &ServiceInfo, kind: OperationKind) -> Result<(), TvcError> {
    if info.supported_operations.contains(&kind) {
        Ok(())
    } else {
        Err(TvcError::new(ErrorCode::ReleaseBindingMismatch))
    }
}

#[cfg(test)]
mod tests {
    use qos_p256::encrypt::{P256EncryptPair, P256EncryptPublic};

    #[test]
    fn qos_envelope_round_trips_the_response_key() {
        let pair = P256EncryptPair::generate();
        let public = P256EncryptPublic::from_bytes(&pair.public_key().to_bytes()).unwrap();
        let envelope = public.encrypt(b"opened-note").unwrap();
        let opened = pair.decrypt(&envelope).unwrap();
        assert_eq!(&*opened, b"opened-note");
    }
}
