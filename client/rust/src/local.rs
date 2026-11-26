//! Unattested loopback connector. The endpoint has to be loopback HTTP, and
//! discovery has to match the shared testkit fixture.

use serde::Deserialize;
use spr_tvc_wire::constants::{API_VERSION, QOS_P256_PUBLIC_LEN};
use spr_tvc_wire::decryption_service::SERVICE_PROOF_TYPE;
use spr_tvc_wire::digest::sha256;
use spr_tvc_wire::encoding::{decode_lower_hex, parse_strict_json};
use spr_tvc_wire::error::{ErrorCode, TvcError};
use spr_tvc_wire::types::{
    ManifestSetMember, ManifestSetPolicy, Network, OperationKind, ReleasePolicy, ServiceInfo,
    SignedReleasePolicy,
};

use crate::attestation::{now_ms, IdentityPcrs};
use crate::session::{bind_discovery, join, ping_challenge, verify_ping, Session};
use crate::transport::{discovery_limit, Transport};
use crate::ClientError;

const TESTKIT_JSON: &str = include_str!("../../../tests/fixtures/local-testkit.json");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Testkit {
    version: u8,
    release_id: String,
    quorum_key_id: String,
    security_domain_label: String,
    manifest_label: String,
    executable_label: String,
    quorum_public_key: String,
    ephemeral_public_key: String,
    operations: Vec<OperationKind>,
}

pub(crate) fn connect<T: Transport>(
    endpoint: String,
    transport: T,
) -> Result<(Session<()>, T), ClientError> {
    require_loopback(&endpoint)?;
    let testkit: Testkit = parse_strict_json(TESTKIT_JSON)?;
    if testkit.version != 1 {
        return Err(TvcError::new(ErrorCode::DiscoveryUntrusted).into());
    }
    let info_bytes = transport.get(&join(&endpoint, "/v1/info"), discovery_limit())?;
    let info_text = std::str::from_utf8(&info_bytes)
        .map_err(|_| TvcError::new(ErrorCode::DiscoveryUntrusted))?;
    let info: ServiceInfo = parse_strict_json(info_text)?;
    let release = release_for(&testkit, &info)?;
    bind_discovery(&info, &release)?;
    let (body, payload) = ping_challenge(&info.quorum_public_key)?;
    let ping_bytes = transport.post(&join(&endpoint, "/v1/ping"), &body, discovery_limit())?;
    let ping_text = std::str::from_utf8(&ping_bytes)
        .map_err(|_| TvcError::new(ErrorCode::BootProofUnverified))?;
    let proof = verify_ping(ping_text, &payload)?;
    let expected = ephemeral_key(&testkit.ephemeral_public_key)?;
    let signed = ephemeral_key_bytes(&proof.public_key)?;
    if signed != expected {
        return Err(TvcError::new(ErrorCode::DiscoveryUntrusted).into());
    }
    let session = Session::verified(
        endpoint,
        release,
        IdentityPcrs {
            pcr0: [0; 48],
            pcr1: [0; 48],
            pcr2: [0; 48],
            pcr3: [0; 48],
        },
        now_ms,
    )
    .with_loopback_key(expected);
    Ok((session, transport))
}

fn require_loopback(endpoint: &str) -> Result<(), ClientError> {
    let url =
        reqwest::Url::parse(endpoint).map_err(|_| TvcError::new(ErrorCode::DiscoveryUntrusted))?;
    let host = url.host_str();
    if url.scheme() != "http"
        || !matches!(host, Some("127.0.0.1" | "localhost" | "::1"))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(TvcError::new(ErrorCode::DiscoveryUntrusted).into());
    }
    Ok(())
}

fn release_for(testkit: &Testkit, info: &ServiceInfo) -> Result<SignedReleasePolicy, TvcError> {
    if info.version != API_VERSION
        || info.network != Network::Devnet
        || info.release_id != testkit.release_id
        || info.quorum_key_id != testkit.quorum_key_id
        || info.quorum_key_epoch != 1
        || info.proof_type != SERVICE_PROOF_TYPE
        || info.security_domain_id != sha256(testkit.security_domain_label.as_bytes())
        || info.manifest_digest != sha256(testkit.manifest_label.as_bytes())
        || info.executable_digest != sha256(testkit.executable_label.as_bytes())
        || info.quorum_public_key != decode_lower_hex(&testkit.quorum_public_key)?
        || info.supported_operations != testkit.operations
    {
        return Err(TvcError::new(ErrorCode::DiscoveryUntrusted));
    }
    Ok(SignedReleasePolicy {
        policy: ReleasePolicy {
            version: API_VERSION,
            network: info.network,
            security_domain_id: info.security_domain_id,
            namespace: "local".into(),
            manifest_set: local_manifest_set(),
            minimum_manifest_nonce: 0,
            quorum_key_id: info.quorum_key_id.clone(),
            quorum_key_epoch: info.quorum_key_epoch,
            quorum_public_key: info.quorum_public_key.clone(),
            allowed_operations: info.supported_operations.clone(),
            max_encrypted_request_bytes: u32::try_from(info.max_encrypted_request_bytes)
                .map_err(|_| TvcError::new(ErrorCode::DiscoveryUntrusted))?,
            max_encrypted_response_bytes: u32::try_from(info.max_encrypted_response_bytes)
                .map_err(|_| TvcError::new(ErrorCode::DiscoveryUntrusted))?,
            turnkey_trust_root_id: "local-unattested".into(),
            valid_from_ms: 0,
            expires_at_ms: u64::MAX,
            revocation_epoch: 0,
        },
        authority_set_id: "local".into(),
        signatures: Vec::new(),
    })
}

fn local_manifest_set() -> ManifestSetPolicy {
    const GENERATOR: [u8; 65] = [
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
        0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40,
        0x68, 0x37, 0xbf, 0x51, 0xf5,
    ];
    ManifestSetPolicy {
        threshold: 1,
        members: vec![ManifestSetMember {
            alias: "local".into(),
            public_key: [GENERATOR, GENERATOR].concat(),
        }],
    }
}

fn ephemeral_key(hex_key: &str) -> Result<[u8; QOS_P256_PUBLIC_LEN], TvcError> {
    ephemeral_key_bytes(&decode_lower_hex(hex_key)?)
}

fn ephemeral_key_bytes(bytes: &[u8]) -> Result<[u8; QOS_P256_PUBLIC_LEN], TvcError> {
    let key: [u8; QOS_P256_PUBLIC_LEN] = bytes
        .try_into()
        .map_err(|_| TvcError::new(ErrorCode::InvalidPublicKey))?;
    Ok(key)
}
