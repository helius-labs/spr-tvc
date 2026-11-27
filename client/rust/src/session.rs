//! The signed pin is the request target. Each reply is checked on its own.

use qos_p256::encrypt::P256EncryptPair;
#[cfg(feature = "local-dev")]
use qos_p256::encrypt::P256EncryptPublic;
#[cfg(feature = "local-dev")]
use spr_tvc_wire::constants::{API_VERSION, TVC_QOS_PING_PROOF_TYPE};
use spr_tvc_wire::constants::{QOS_P256_PUBLIC_LEN, TVC_APP_PROOF_SCHEME};
use spr_tvc_wire::crypto::verify_p256_message;
#[cfg(feature = "local-dev")]
use spr_tvc_wire::decryption_service::SERVICE_PROOF_TYPE;
#[cfg(feature = "local-dev")]
use spr_tvc_wire::encoding::jcs_serialize;
use spr_tvc_wire::encoding::{is_rfc8785, parse_strict_json};
use spr_tvc_wire::error::{ErrorCode, TvcError};
use spr_tvc_wire::release::{
    verify_signed_release_policy, IdentityPcrs, MainnetTrust, PinnedReleaseAuthorities,
};
use spr_tvc_wire::types::{AppProof, Network, OperationKind, ReleasePolicy, SignedReleasePolicy};
#[cfg(feature = "local-dev")]
use spr_tvc_wire::types::{QosPingChallenge, QosPingRequest, QosPingResponse, ServiceInfo};
use zeroize::Zeroizing;

const MAINNET_TRUST_JSON: &str = include_str!("../../sdk/trust/mainnet.json");

pub(crate) fn pinned_mainnet_trust() -> Result<Option<MainnetTrust>, TvcError> {
    parse_strict_json(MAINNET_TRUST_JSON)
}

pub(crate) fn bind_mainnet_release(
    release: &SignedReleasePolicy,
    authorities: &PinnedReleaseAuthorities,
    pcrs: &IdentityPcrs,
    trust: Option<&MainnetTrust>,
) -> Result<(), TvcError> {
    let trust = trust.ok_or_else(|| TvcError::new(ErrorCode::ReleaseNotPinned))?;
    trust.bind_release(release, authorities, pcrs)
}

pub(crate) fn verify_connection_release(
    network: Network,
    release: &SignedReleasePolicy,
    authorities: &PinnedReleaseAuthorities,
    pcrs: &IdentityPcrs,
    now: u64,
) -> Result<(), TvcError> {
    if network == Network::Mainnet {
        let trust = pinned_mainnet_trust()?;
        bind_mainnet_release(release, authorities, pcrs, trust.as_ref())?;
    }
    verify_signed_release_policy(release, authorities, network, now)
}

use crate::attestation::{approved_manifest_digest, now_ms, verify_boot_proof, BootProof};
use crate::transport::Transport;
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
        Err(TvcError::boot("decode").into())
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
        let now = if config.network == Network::Mainnet {
            now_ms
        } else {
            config.now_ms.unwrap_or(now_ms)
        };
        verify_connection_release(
            config.network,
            &config.release,
            &config.authorities,
            &config.pcrs,
            now(),
        )?;
        Ok((
            Self {
                endpoint: config.endpoint,
                release: config.release,
                pcrs: config.pcrs,
                boot_proofs: config.boot_proofs,
                now_ms: now,
                expected_ephemeral: None,
            },
            config.transport,
        ))
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
        release: SignedReleasePolicy,
        pcrs: IdentityPcrs,
        now_ms: fn() -> u64,
    ) -> Self {
        Self {
            endpoint,
            release,
            pcrs,
            boot_proofs: (),
            now_ms,
            expected_ephemeral: None,
        }
    }

    #[cfg(feature = "local-dev")]
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
    let digest = approved_manifest_digest(&boot.manifest_envelope, &release.policy, pcrs)?;
    verify_boot_proof(&key, &boot, &digest, pcrs, now)?;
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
    let digest = approved_manifest_digest(&boot.manifest_envelope, &release.policy, pcrs)?;
    verify_boot_proof(&key, boot, &digest, pcrs, now)?;
    Ok(())
}

#[cfg(feature = "local-dev")]
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
    if info.security_domain_id != policy.security_domain_id
        || info.quorum_key_id != policy.quorum_key_id
        || info.quorum_public_key != policy.quorum_public_key
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

#[cfg(feature = "local-dev")]
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

#[cfg(feature = "local-dev")]
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

#[cfg(feature = "local-dev")]
fn parse_qos_ping_response(text: &str) -> Result<QosPingResponse, TvcError> {
    spr_tvc_wire::encoding::parse_strict_json(text)
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

pub(crate) fn ensure_operation(
    policy: &ReleasePolicy,
    kind: OperationKind,
) -> Result<(), TvcError> {
    if policy.allowed_operations.contains(&kind) {
        Ok(())
    } else {
        Err(TvcError::new(ErrorCode::ReleaseBindingMismatch))
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;
    use qos_p256::encrypt::{P256EncryptPair, P256EncryptPublic};
    use spr_tvc_wire::constants::{API_VERSION, EXPECTED_TURNKEY_TRUST_ROOT_ID};
    use spr_tvc_wire::release::{sign_release_policy, ReleaseAuthorityKey};
    use spr_tvc_wire::types::{ManifestSetMember, ManifestSetPolicy, ReleaseAuthoritySignature};

    use super::*;

    #[test]
    fn qos_envelope_round_trips_the_response_key() {
        let pair = P256EncryptPair::generate();
        let public = P256EncryptPublic::from_bytes(&pair.public_key().to_bytes()).unwrap();
        let envelope = public.encrypt(b"opened-note").unwrap();
        let opened = pair.decrypt(&envelope).unwrap();
        assert_eq!(&*opened, b"opened-note");
    }

    fn mainnet_fixture() -> (
        SignedReleasePolicy,
        PinnedReleaseAuthorities,
        IdentityPcrs,
        MainnetTrust,
    ) {
        let s1 = [11u8; 32];
        let s2 = [12u8; 32];
        let p1 = SigningKey::from_slice(&s1)
            .unwrap()
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let p2 = SigningKey::from_slice(&s2)
            .unwrap()
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let quorum = [p1.as_slice(), p2.as_slice()].concat();
        let policy = ReleasePolicy {
            version: API_VERSION,
            network: Network::Mainnet,
            security_domain_id: [0x22; 32],
            namespace: "prod".into(),
            manifest_set: ManifestSetPolicy {
                threshold: 1,
                members: vec![ManifestSetMember {
                    alias: "op".into(),
                    public_key: quorum.clone(),
                }],
            },
            minimum_manifest_nonce: 0,
            quorum_key_id: "prod-quorum".into(),
            quorum_key_epoch: 1,
            quorum_public_key: quorum.clone(),
            allowed_operations: vec![
                OperationKind::ServicePublicKeys,
                OperationKind::ServiceDecrypt,
            ],
            max_encrypted_request_bytes: 1_000_000,
            max_encrypted_response_bytes: 1_000_000,
            turnkey_trust_root_id: EXPECTED_TURNKEY_TRUST_ROOT_ID.into(),
            valid_from_ms: 1_700_000_000_000,
            expires_at_ms: 1_700_086_400_000,
            revocation_epoch: 1,
        };
        let authorities = PinnedReleaseAuthorities {
            authority_set_id: "mainnet-v1".into(),
            threshold: 2,
            keys: vec![
                ReleaseAuthorityKey {
                    key_id: "k1".into(),
                    public_key: p1,
                },
                ReleaseAuthorityKey {
                    key_id: "k2".into(),
                    public_key: p2,
                },
            ],
            minimum_revocation_epoch: 1,
        };
        let signed = SignedReleasePolicy {
            signatures: vec![
                ReleaseAuthoritySignature {
                    key_id: "k1".into(),
                    signature: sign_release_policy(&policy, &s1).unwrap().to_vec(),
                },
                ReleaseAuthoritySignature {
                    key_id: "k2".into(),
                    signature: sign_release_policy(&policy, &s2).unwrap().to_vec(),
                },
            ],
            authority_set_id: "mainnet-v1".into(),
            policy,
        };
        let pcrs = IdentityPcrs {
            pcr0: [1; 48],
            pcr1: [2; 48],
            pcr2: [3; 48],
            pcr3: [4; 48],
        };
        let trust = MainnetTrust {
            release_authorities: authorities.clone(),
            qos_identity_pcrs: pcrs,
            security_domain_id: [0x22; 32],
            quorum_public_key: quorum,
            maximum_policy_lifetime_ms: 86_400_000,
        };
        (signed, authorities, pcrs, trust)
    }

    #[test]
    fn mainnet_binding_fails_closed_when_unpinned_and_validates_anchors() {
        let (signed, authorities, pcrs, trust) = mainnet_fixture();
        assert_eq!(
            bind_mainnet_release(&signed, &authorities, &pcrs, None)
                .unwrap_err()
                .code,
            ErrorCode::ReleaseNotPinned
        );
        bind_mainnet_release(&signed, &authorities, &pcrs, Some(&trust)).unwrap();

        let mut wrong_pcrs = pcrs;
        wrong_pcrs.pcr0[0] ^= 1;
        assert_eq!(
            bind_mainnet_release(&signed, &authorities, &wrong_pcrs, Some(&trust))
                .unwrap_err()
                .code,
            ErrorCode::ReleasePolicyInvalid
        );

        let mut over_lifetime = signed.clone();
        over_lifetime.policy.expires_at_ms += 1;
        assert_eq!(
            bind_mainnet_release(&over_lifetime, &authorities, &pcrs, Some(&trust))
                .unwrap_err()
                .code,
            ErrorCode::ReleasePolicyInvalid
        );

        let single_sig_trust = MainnetTrust {
            release_authorities: PinnedReleaseAuthorities {
                threshold: 1,
                ..authorities.clone()
            },
            qos_identity_pcrs: pcrs,
            security_domain_id: trust.security_domain_id,
            quorum_public_key: trust.quorum_public_key.clone(),
            maximum_policy_lifetime_ms: trust.maximum_policy_lifetime_ms,
        };
        assert_eq!(
            bind_mainnet_release(
                &signed,
                &single_sig_trust.release_authorities,
                &pcrs,
                Some(&single_sig_trust)
            )
            .unwrap_err()
            .code,
            ErrorCode::ReleasePolicyInvalid
        );
        assert_eq!(
            verify_connection_release(
                Network::Mainnet,
                &signed,
                &authorities,
                &pcrs,
                1_700_000_000_001,
            )
            .unwrap_err()
            .code,
            ErrorCode::ReleaseNotPinned
        );
    }
}
