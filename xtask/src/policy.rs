use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::Generate;
use qos_core::protocol::services::boot::manifest::VersionedManifest;
use serde::{Deserialize, Serialize};
use serde_json::json;
use spr_tvc_protocol::constants::{
    API_VERSION, EXPECTED_TURNKEY_TRUST_ROOT_ID, MAX_ENCRYPTED_REQUEST_BYTES,
    MAX_ENCRYPTED_RESPONSE_BYTES,
};
use spr_tvc_protocol::crypto::{parse_uncompressed_sec1, public_key_uncompressed, QosP256Public};
use spr_tvc_protocol::decryption_service::SERVICE_PROOF_TYPE;
use spr_tvc_protocol::encoding::hex as wire_hex;
use spr_tvc_protocol::release::{
    policy_signing_digest, sign_release_policy, verify_signed_release_policy,
    PinnedReleaseAuthorities, ReleaseAuthorityKey,
};
use spr_tvc_protocol::types::{
    Network, OperationKind, ReleaseAuthoritySignature, ReleasePolicy, ServiceInfo,
    SignedReleasePolicy,
};
use zeroize::Zeroizing;

use crate::deploy::{Deployment, Descriptor};
use crate::tools::{capture, verify_live, Credentials};
use crate::{app_config, lower_hex, read_json, write_json, Pcrs, Phase, Release};

const OPERATIONS: [OperationKind; 2] = [
    OperationKind::ServicePublicKeys,
    OperationKind::ServiceDecrypt,
];
const DAY_MS: u64 = 86_400_000;
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainnetTrust {
    release_authorities: PinnedReleaseAuthorities,
    qos_identity_pcrs: Pcrs,
    #[serde(with = "wire_hex")]
    security_domain_id: [u8; 32],
    #[serde(with = "wire_hex")]
    quorum_public_key: Vec<u8>,
    maximum_policy_lifetime_ms: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TurnkeyDeployment {
    id: String,
    organization_id: String,
    app_id: String,
    qos_version: String,
    debug_mode: bool,
    #[serde(default)]
    delete: bool,
    pivot_container: Option<Pivot>,
    manifest: Manifest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Pivot {
    container_url: String,
}

#[derive(Deserialize)]
struct Manifest {
    manifest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Approved {
    manifest_digest: String,
    executable_digest: String,
    #[serde(with = "wire_hex")]
    quorum_public_key: Vec<u8>,
}

impl TurnkeyDeployment {
    fn approve(
        &self,
        release: &Release<'_>,
        deploy_id: &str,
        organization_id: &str,
        descriptor: &Descriptor,
        quorum_public_key: &[u8],
    ) -> Result<Approved> {
        let mainnet = release.network() == Network::Mainnet;
        ensure!(
            !self.debug_mode
                && !self.delete
                && self.id == deploy_id
                && self.organization_id == organization_id
                && self.app_id == release.app.app_id
                && self.qos_version == release.qos_version(),
            "deployment does not match the approved app and QOS runtime"
        );
        if mainnet {
            ensure!(
                self.pivot_container.as_ref().is_some_and(
                    |pivot| pivot.container_url == descriptor.pivot_container_image_url
                ),
                "deployment does not match the attested image reference"
            );
        }
        let encoded = &self.manifest.manifest;
        ensure!(
            !encoded.is_empty() && encoded.len() <= 1_048_576,
            "deployment has no supported manifest"
        );
        let manifest = VersionedManifest::V2(serde_json::from_slice(&STANDARD.decode(encoded)?)?);
        if mainnet {
            ensure!(
                manifest.manifest_set().threshold >= 2 && manifest.share_set().threshold >= 2,
                "mainnet requires threshold manifest approval and share recovery"
            );
        }
        let executable_digest = hex::encode(manifest.pivot_hash());
        ensure!(
            executable_digest == descriptor.expected_pivot_digest,
            "approved manifest does not match the locally built executable"
        );
        ensure!(
            manifest.namespace().quorum_key == quorum_public_key,
            "approved manifest does not match the configured Quorum public key"
        );
        Ok(Approved {
            manifest_digest: hex::encode(manifest.manifest_hash()),
            executable_digest,
            quorum_public_key: quorum_public_key.to_vec(),
        })
    }
}

impl Release<'_> {
    pub(crate) fn production_trust(&self) -> Result<MainnetTrust> {
        let trust: MainnetTrust =
            read_json::<Option<_>>(std::path::Path::new("sdk/trust/mainnet.json"))?
                .context("mainnet trust anchors are unavailable")?;
        let mainnet = app_config(Network::Mainnet)?;
        let devnet = &self.config.networks.devnet;
        let devnet_key = app_config(Network::Devnet)?.quorum_public_key;
        ensure!(
            trust.security_domain_id == self.app.security_domain_id
                && trust.quorum_public_key == mainnet.quorum_public_key,
            "mainnet app must match the independently pinned Quorum key and security domain"
        );
        ensure!(
            devnet.app_id != self.app.app_id
                && devnet.security_domain_id != trust.security_domain_id
                && devnet_key != trust.quorum_public_key,
            "mainnet and devnet require separate apps, domains, and Quorum keys"
        );
        if let Some(previous) = read_json::<Option<SignedReleasePolicy>>(&self.pin_path())? {
            ensure!(
                previous.policy.security_domain_id == trust.security_domain_id
                    && previous.policy.quorum_public_key == trust.quorum_public_key,
                "changing the pinned Quorum domain requires recipient migration"
            );
        }
        trust.validate()?;
        Ok(trust)
    }

    pub(crate) fn approved_deployment(
        &self,
        deploy_id: &str,
        descriptor: &Descriptor,
        credentials: &Credentials,
    ) -> Result<Approved> {
        let deployment: TurnkeyDeployment = serde_json::from_slice(&capture(
            &mut credentials.bridge(&["deployment", deploy_id]),
        )?)
        .context("decode authenticated Turnkey deployment")?;
        let app = app_config(self.network())?;
        QosP256Public::from_bytes(&app.quorum_public_key)?;
        deployment.approve(
            self,
            deploy_id,
            &credentials.organization_id,
            descriptor,
            &app.quorum_public_key,
        )
    }

    fn release_policy(
        &self,
        info: &ServiceInfo,
        approved: &Approved,
        trust: Option<&MainnetTrust>,
        valid_from_ms: u64,
    ) -> Result<ReleasePolicy> {
        ensure!(
            self.config.turnkey_trust_root_id == EXPECTED_TURNKEY_TRUST_ROOT_ID,
            "unexpected Turnkey trust root"
        );
        ensure!(
            info.version == API_VERSION
                && info.proof_type == SERVICE_PROOF_TYPE
                && info.network == self.network()
                && info.security_domain_id == self.app.security_domain_id
                && info.release_id == self.args.release_id
                && info.quorum_key_id == self.app.quorum_key_id
                && info.quorum_key_epoch == self.app.quorum_key_epoch
                && info.supported_operations == OPERATIONS
                && info.max_encrypted_request_bytes == MAX_ENCRYPTED_REQUEST_BYTES
                && info.max_encrypted_response_bytes == MAX_ENCRYPTED_RESPONSE_BYTES
                && hex::encode(info.manifest_digest) == approved.manifest_digest
                && hex::encode(info.executable_digest) == approved.executable_digest
                && info.quorum_public_key == approved.quorum_public_key,
            "/v1/info does not match the release and approved manifest"
        );
        let (lifetime, epoch) = match trust {
            Some(trust) => {
                ensure!(
                    info.security_domain_id == trust.security_domain_id
                        && approved.quorum_public_key == trust.quorum_public_key,
                    "candidate must match independently pinned mainnet trust"
                );
                (
                    trust.maximum_policy_lifetime_ms,
                    trust.release_authorities.minimum_revocation_epoch,
                )
            }
            None => (
                self.config
                    .policy_validity_days
                    .checked_mul(DAY_MS)
                    .context("invalid policy validity days")?,
                0,
            ),
        };
        let expires_at_ms = valid_from_ms
            .checked_add(lifetime)
            .context("policy expiry overflow")?;
        ensure!(
            valid_from_ms > 0 && expires_at_ms > valid_from_ms && expires_at_ms <= MAX_SAFE_INTEGER,
            "invalid policy lifetime"
        );
        Ok(ReleasePolicy {
            version: API_VERSION,
            release_id: self.args.release_id.clone(),
            network: self.network(),
            security_domain_id: self.app.security_domain_id,
            accepted_manifest_digests: vec![approved.manifest_digest.clone()],
            accepted_executable_digests: vec![approved.executable_digest.clone()],
            quorum_key_id: self.app.quorum_key_id.clone(),
            quorum_key_epoch: self.app.quorum_key_epoch,
            quorum_public_key: approved.quorum_public_key.clone(),
            allowed_operations: OPERATIONS.to_vec(),
            max_encrypted_request_bytes: MAX_ENCRYPTED_REQUEST_BYTES as u32,
            max_encrypted_response_bytes: MAX_ENCRYPTED_RESPONSE_BYTES as u32,
            turnkey_trust_root_id: self.config.turnkey_trust_root_id.clone(),
            valid_from_ms,
            expires_at_ms,
            revocation_epoch: epoch,
        })
    }

    pub(crate) fn policy(&self) -> Result<()> {
        let mainnet = self.network() == Network::Mainnet;
        let trust = mainnet.then(|| self.production_trust()).transpose()?;
        let record: Deployment = read_json(&self.path("deploy"))?;
        ensure!(
            (mainnet || record.live)
                && self.live_deployment()?.as_deref() == Some(&record.deploy_id),
            "the recorded deployment is not live"
        );
        let descriptor: Descriptor = read_json(&self.path("deployment"))?;
        self.verify_image(&descriptor.pivot_container_image_url)?;
        let credentials = Credentials::load()?;
        let approved = self.approved_deployment(&record.deploy_id, &descriptor, &credentials)?;
        let info = self.await_info(&descriptor)?;
        let signed: Option<SignedReleasePolicy> = self
            .args
            .signed_policy
            .as_deref()
            .map(read_json)
            .transpose()?;
        let valid_from_ms = signed
            .as_ref()
            .map_or_else(now_ms, |signed| Ok(signed.policy.valid_from_ms))?;
        let policy = self.release_policy(&info, &approved, trust.as_ref(), valid_from_ms)?;
        let pcrs = trust
            .as_ref()
            .map_or(&self.config.qos_identity_pcrs, |trust| {
                &trust.qos_identity_pcrs
            });
        validate_pcrs(pcrs)?;
        if let Some(signed) = &signed {
            verify_mainnet_policy(
                signed,
                &policy,
                trust.as_ref().context("missing mainnet trust")?,
                now_ms()?,
            )?;
        }

        verify_live(
            &credentials,
            &json!({
                "endpoint": self.app.endpoint,
                "info": info,
                "approved": approved,
                "qosIdentityPcrs": pcrs,
                "turnkeyTrustRootId": self.config.turnkey_trust_root_id,
            }),
        )?;
        println!(
            "verified live manifest {} at {}",
            approved.manifest_digest, self.app.endpoint
        );

        match (trust.as_ref(), signed) {
            (Some(trust), Some(signed)) => {
                verify_mainnet_policy(&signed, &policy, trust, now_ms()?)?;
                write_json(&self.pin_path(), &signed)
            }
            (Some(trust), None) if self.args.phase == Phase::Prepare => {
                let policy = self.release_policy(&info, &approved, Some(trust), now_ms()?)?;
                write_json(
                    &self.path("policy-request"),
                    &json!({
                        "digest": hex::encode(policy_signing_digest(&policy)?),
                        "authoritySetId": trust.release_authorities.authority_set_id,
                        "policy": policy,
                    }),
                )
            }
            (None, None) => {
                let (signed, authorities) = devnet_sign(policy)?;
                write_json(
                    &self.pin_path(),
                    &json!({
                        "releasePolicy": signed,
                        "releaseAuthorities": authorities,
                        "qosIdentityPcrs": pcrs,
                    }),
                )
            }
            _ => anyhow::bail!("inconsistent release phase and signing inputs"),
        }
    }
}

impl MainnetTrust {
    fn validate(&self) -> Result<()> {
        let authorities = &self.release_authorities;
        ensure!(
            authorities.threshold >= 2
                && usize::from(authorities.threshold) <= authorities.keys.len(),
            "mainnet requires two or more distinct release authorities"
        );
        let mut ids = std::collections::HashSet::new();
        let mut public_keys = std::collections::HashSet::new();
        for key in &authorities.keys {
            parse_uncompressed_sec1(&key.public_key)?;
            ensure!(
                ids.insert(&key.key_id) && public_keys.insert(&key.public_key),
                "duplicate release authority"
            );
        }
        ensure!(
            (1..=MAX_SAFE_INTEGER).contains(&self.maximum_policy_lifetime_ms),
            "invalid mainnet policy lifetime"
        );
        QosP256Public::from_bytes(&self.quorum_public_key)?;
        validate_pcrs(&self.qos_identity_pcrs)
    }
}

fn validate_pcrs(pcrs: &Pcrs) -> Result<()> {
    ensure!(
        pcrs.len() == 4 && (0..=3).all(|i| pcrs.get(&i).is_some_and(|pcr| lower_hex(pcr, 96))),
        "expected four pinned 48-byte PCRs"
    );
    Ok(())
}

fn now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

fn verify_mainnet_policy(
    signed: &SignedReleasePolicy,
    expected: &ReleasePolicy,
    trust: &MainnetTrust,
    now: u64,
) -> Result<()> {
    ensure!(
        &signed.policy == expected,
        "signed mainnet policy does not match the attested candidate"
    );
    verify_signed_release_policy(signed, &trust.release_authorities, Network::Mainnet, now)?;
    Ok(())
}

fn devnet_sign(policy: ReleasePolicy) -> Result<(SignedReleasePolicy, PinnedReleaseAuthorities)> {
    ensure!(
        policy.network == Network::Devnet,
        "mainnet requires independent release authorities"
    );
    let signing_key =
        SigningKey::try_generate().map_err(|_| anyhow::anyhow!("generate devnet signing key"))?;
    let secret = Zeroizing::new(signing_key.to_bytes().into());
    let public = p256::PublicKey::from(signing_key.verifying_key());
    let authority_set_id = format!("{}-{}", policy.release_id, policy.valid_from_ms);
    let key_id = format!("{}-authority-1", policy.release_id);
    let signature = sign_release_policy(&policy, &secret)?.to_vec();
    let authorities = PinnedReleaseAuthorities {
        authority_set_id: authority_set_id.clone(),
        threshold: 1,
        minimum_revocation_epoch: 0,
        keys: vec![ReleaseAuthorityKey {
            key_id: key_id.clone(),
            public_key: public_key_uncompressed(&public).to_vec(),
        }],
    };
    let now = policy.valid_from_ms;
    let signed = SignedReleasePolicy {
        policy,
        authority_set_id,
        signatures: vec![ReleaseAuthoritySignature { key_id, signature }],
    };
    verify_signed_release_policy(&signed, &authorities, Network::Devnet, now)?;
    Ok((signed, authorities))
}

#[cfg(test)]
#[path = "../tests/policy.rs"]
mod tests;
