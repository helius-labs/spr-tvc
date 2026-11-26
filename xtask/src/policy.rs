use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::Generate;
use qos_core::protocol::services::boot::manifest::{canonical_json_hash, ManifestV2};
use qos_p256::P256Public;
use serde::{Deserialize, Serialize};
use serde_json::json;
use spr_tvc_wire::constants::{
    API_VERSION, EXPECTED_TURNKEY_TRUST_ROOT_ID, MAX_ENCRYPTED_POLICY_BYTES,
    MAX_ENCRYPTED_REQUEST_BYTES, MAX_ENCRYPTED_RESPONSE_BYTES,
};
use spr_tvc_wire::crypto::{parse_uncompressed_sec1, public_key_uncompressed};
use spr_tvc_wire::decryption_service::SERVICE_PROOF_TYPE;
use spr_tvc_wire::encoding::hex as wire_hex;
use spr_tvc_wire::release::{
    policy_signing_digest, sign_release_policy, verify_signed_release_policy,
    PinnedReleaseAuthorities, ReleaseAuthorityKey,
};
use spr_tvc_wire::types::{
    ManifestSetMember, ManifestSetPolicy, Network, OperationKind, ReleaseAuthoritySignature,
    ReleasePolicy, ServiceInfo, SignedReleasePolicy,
};
use zeroize::Zeroizing;

use crate::stage::Descriptor;
use crate::tools::{capture_check, verify_live, Credentials};
use crate::{app_config, lower_hex, read_json, write_json, Pcrs, Release};

pub(crate) const OPERATIONS: [OperationKind; 2] = [
    OperationKind::ServicePublicKeys,
    OperationKind::ServiceDecrypt,
];
const DAY_MS: u64 = 86_400_000;
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainnetTrust {
    pub(crate) release_authorities: PinnedReleaseAuthorities,
    pub(crate) qos_identity_pcrs: Pcrs,
    #[serde(with = "wire_hex")]
    pub(crate) security_domain_id: [u8; 32],
    #[serde(with = "wire_hex")]
    pub(crate) quorum_public_key: Vec<u8>,
    pub(crate) maximum_policy_lifetime_ms: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TurnkeyDeployment {
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
    pub(crate) manifest_digest: String,
    pub(crate) executable_digest: String,
    #[serde(with = "wire_hex")]
    pub(crate) quorum_public_key: Vec<u8>,
    pub(crate) namespace: String,
    pub(crate) manifest_set: ManifestSetPolicy,
}

impl TurnkeyDeployment {
    pub(crate) fn approve(
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
        let tagged_image = &descriptor.pivot_container_image_url;
        let (_, digest) = tagged_image
            .split_once("@sha256:")
            .context("missing image digest")?;
        let canonical_image = format!("{}@sha256:{digest}", release.config.image_repository);
        ensure!(
            self.pivot_container
                .as_ref()
                .is_some_and(|pivot| &pivot.container_url == tagged_image
                    || pivot.container_url == canonical_image),
            "deployment does not match the reviewed image digest"
        );
        let encoded = &self.manifest.manifest;
        ensure!(
            !encoded.is_empty() && encoded.len() <= 1_048_576,
            "deployment has no supported manifest"
        );
        let manifest: ManifestV2 = serde_json::from_slice(&STANDARD.decode(encoded)?)?;
        ensure!(
            manifest.pivot.args == descriptor.pivot_args
                && !manifest.pivot.debug_mode
                && manifest.pivot.env.is_empty(),
            "measured launch arguments, environment, or debug mode differ from the descriptor"
        );
        if mainnet {
            ensure!(
                manifest.manifest_set.threshold >= 2 && manifest.share_set.threshold >= 2,
                "mainnet requires threshold manifest approval and share recovery"
            );
        }
        let executable_digest = hex::encode(manifest.pivot.hash);
        ensure!(
            executable_digest == descriptor.expected_pivot_digest,
            "approved manifest does not match the locally built executable"
        );
        ensure!(
            manifest.namespace.quorum_key == quorum_public_key,
            "approved manifest does not match the configured Quorum public key"
        );
        Ok(Approved {
            manifest_digest: hex::encode(canonical_json_hash(&manifest)),
            executable_digest,
            quorum_public_key: quorum_public_key.to_vec(),
            namespace: manifest.namespace.name.clone(),
            manifest_set: ManifestSetPolicy {
                threshold: manifest.manifest_set.threshold,
                members: manifest
                    .manifest_set
                    .members
                    .iter()
                    .map(|member| ManifestSetMember {
                        alias: member.alias.clone(),
                        public_key: member.pub_key.clone(),
                    })
                    .collect(),
            },
        })
    }
}

impl Release<'_> {
    pub(crate) fn production_trust(&self) -> Result<MainnetTrust> {
        let trust: MainnetTrust =
            read_json::<Option<_>>(std::path::Path::new("client/sdk/trust/mainnet.json"))?
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
        let deployment: TurnkeyDeployment = serde_json::from_slice(&capture_check(
            &mut credentials.bridge(&["deployment", deploy_id]),
        )?)
        .context("decode authenticated Turnkey deployment")?;
        let app = app_config(self.network())?;
        P256Public::from_bytes(&app.quorum_public_key)
            .map_err(|error| anyhow::anyhow!("invalid Turnkey app Quorum key ({error:?})"))?;
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
        minimum_manifest_nonce: u64,
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
            network: self.network(),
            security_domain_id: self.app.security_domain_id,
            namespace: approved.namespace.clone(),
            manifest_set: approved.manifest_set.clone(),
            minimum_manifest_nonce,
            quorum_key_id: self.app.quorum_key_id.clone(),
            quorum_key_epoch: self.app.quorum_key_epoch,
            quorum_public_key: approved.quorum_public_key.clone(),
            allowed_operations: OPERATIONS.to_vec(),
            max_encrypted_request_bytes: MAX_ENCRYPTED_POLICY_BYTES,
            max_encrypted_response_bytes: MAX_ENCRYPTED_POLICY_BYTES,
            turnkey_trust_root_id: self.config.turnkey_trust_root_id.clone(),
            valid_from_ms,
            expires_at_ms,
            revocation_epoch: epoch,
        })
    }

    pub(crate) fn pin(&self) -> Result<()> {
        let mainnet = self.network() == Network::Mainnet;
        let trust = mainnet.then(|| self.production_trust()).transpose()?;
        let deploy_id = self
            .args
            .deploy_id
            .clone()
            .context("pin requires the live deploy id")?;
        ensure!(
            self.live_deployment()?.as_deref() == Some(deploy_id.as_str()),
            "the deployment is not live"
        );
        let descriptor = self.measured_descriptor()?;
        let credentials = Credentials::load()?;
        let approved = self.approved_deployment(&deploy_id, &descriptor, &credentials)?;
        let info = self.live_info()?;
        let signed: Option<SignedReleasePolicy> = self
            .args
            .signed_policy
            .as_deref()
            .map(read_json)
            .transpose()?;
        let valid_from_ms = signed
            .as_ref()
            .map_or_else(now_ms, |signed| Ok(signed.policy.valid_from_ms))?;
        let minimum_manifest_nonce = signed
            .as_ref()
            .map_or(self.args.minimum_manifest_nonce, |signed| {
                signed.policy.minimum_manifest_nonce
            });
        ensure!(
            u32::try_from(minimum_manifest_nonce).is_ok(),
            "manifest nonce floor does not fit the client pin"
        );
        let policy = self.release_policy(
            &info,
            &approved,
            trust.as_ref(),
            valid_from_ms,
            minimum_manifest_nonce,
        )?;
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
                println!("verified signed mainnet policy for {}", self.app.endpoint);
                Ok(())
            }
            (Some(trust), None) => {
                let policy = self.release_policy(
                    &info,
                    &approved,
                    Some(trust),
                    now_ms()?,
                    self.args.minimum_manifest_nonce,
                )?;
                write_json(
                    &self.request_path(),
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
            _ => anyhow::bail!("inconsistent pin inputs"),
        }
    }
}

pub(crate) fn deployment_container_url(deploy_id: &str) -> Result<String> {
    let credentials = Credentials::load()?;
    let deployment: TurnkeyDeployment = serde_json::from_slice(&capture_check(
        &mut credentials.bridge(&["deployment", deploy_id]),
    )?)
    .context("decode authenticated Turnkey deployment")?;
    deployment
        .pivot_container
        .context("deployment has no image")
        .map(|pivot| pivot.container_url)
}

impl MainnetTrust {
    pub(crate) fn validate(&self) -> Result<()> {
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
        P256Public::from_bytes(&self.quorum_public_key)
            .map_err(|error| anyhow::anyhow!("invalid pinned Quorum key ({error:?})"))?;
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

pub(crate) fn verify_mainnet_policy(
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

pub(crate) fn devnet_sign(
    policy: ReleasePolicy,
) -> Result<(SignedReleasePolicy, PinnedReleaseAuthorities)> {
    ensure!(
        policy.network == Network::Devnet,
        "mainnet requires independent release authorities"
    );
    let signing_key =
        SigningKey::try_generate().map_err(|_| anyhow::anyhow!("generate devnet signing key"))?;
    let secret = Zeroizing::new(signing_key.to_bytes().into());
    let public = p256::PublicKey::from(signing_key.verifying_key());
    let authority_set_id = format!("{}-{}", policy.quorum_key_id, policy.valid_from_ms);
    let key_id = format!("{}-authority-1", policy.quorum_key_id);
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
