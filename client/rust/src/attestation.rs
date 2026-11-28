//! Boot Proof checks beyond Turnkey's combined verifier.
//!
//! This module checks the COSE signature, the Nitro certificate chain,
//! PCR0–3, PCR17, the manifest the pinned set approved, the replica key, and
//! freshness. Turnkey's `verify` skips the image pins and expects a
//! `timestampMs` field these proofs do not carry.

use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use p384::pkcs8::DecodePublicKey;
use rustls_pki_types::{CertificateDer, UnixTime};
use sha2::{Digest, Sha256, Sha384};
use spr_tvc_wire::constants::{MAX_CLOCK_SKEW_MS, QOS_P256_PUBLIC_LEN, SHA256_LEN, SHA384_LEN};
use spr_tvc_wire::encoding::encode_lower_hex;
use spr_tvc_wire::error::{ErrorCode, TvcError};
pub use spr_tvc_wire::release::IdentityPcrs;
use spr_tvc_wire::types::ReleasePolicy;
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage};
use x509_cert::der::oid::AssociatedOid;
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::{KeyUsage as X509KeyUsage, KeyUsages};
use x509_cert::Certificate;

use crate::cbor::{decode_cbor, decode_nitro_cbor, encode_cose_sig_structure, Cbor, CborKey};

const PCR_COUNT: usize = 32;
const PCR17: i64 = 17;
const COSE_SIGN1_LEN: usize = 4;
const COSE_HEADER_ALG: i64 = 1;
const COSE_ALG_ES384: i64 = -35;
const LIVE_MANIFEST_DOMAIN: &str = "qos-live-manifest-pcr-commitment-v1";
const PEM_CERT_LABEL: &str = "CERTIFICATE";
const AWS_ROOT_SHA256: &str = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b";
const AWS_NITRO_ROOT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL\n\
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD\n\
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4\n\
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL\n\
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG\n\
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb\n\
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE\n\
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF\n\
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC\n\
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW\n\
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N\n\
IwLz3/Y=\n\
-----END CERTIFICATE-----";

/// The attestation document and the ephemeral key the Boot Proof names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootProof {
    pub attestation: Vec<u8>,
    pub ephemeral_public_key: [u8; QOS_P256_PUBLIC_LEN],
    /// QOS manifest envelope. Empty on the synthetic documents the chain tests build.
    pub manifest_envelope: Vec<u8>,
}

/// The manifest hash when the pinned manifest set approved this envelope.
pub(crate) fn approved_manifest_digest(
    envelope: &[u8],
    policy: &ReleasePolicy,
    pcrs: &IdentityPcrs,
) -> Result<[u8; SHA256_LEN], TvcError> {
    use qos_core::protocol::services::boot::manifest::{
        canonical_json_hash, VersionedManifestEnvelope,
    };

    let fail = || TvcError::boot("manifest");
    let versioned =
        VersionedManifestEnvelope::try_from_slice_compat(envelope).map_err(|_| fail())?;
    let VersionedManifestEnvelope::V2(parsed) = &versioned else {
        return Err(fail());
    };
    let manifest = &parsed.manifest;
    let set = &manifest.manifest_set;
    if set.threshold != policy.manifest_set.threshold
        || !same_manifest_set(&policy.manifest_set.members, &set.members)
    {
        return Err(fail());
    }
    versioned.check_approvals().map_err(|_| fail())?;
    let floor = u32::try_from(policy.minimum_manifest_nonce).map_err(|_| fail())?;
    if manifest.pivot.debug_mode
        || !manifest.pivot.env.is_empty()
        || manifest.namespace.name != policy.namespace
        || manifest.namespace.nonce < floor
        || manifest.namespace.quorum_key != policy.quorum_public_key
        || !pcr_bytes(&manifest.enclave.pcr0, &pcrs.pcr0)
        || !pcr_bytes(&manifest.enclave.pcr1, &pcrs.pcr1)
        || !pcr_bytes(&manifest.enclave.pcr2, &pcrs.pcr2)
        || !pcr_bytes(&manifest.enclave.pcr3, &pcrs.pcr3)
    {
        return Err(fail());
    }
    Ok(canonical_json_hash(manifest))
}

fn same_manifest_set(
    pinned: &[spr_tvc_wire::types::ManifestSetMember],
    live: &[qos_core::protocol::services::boot::QuorumMember],
) -> bool {
    pinned.len() == live.len()
        && pinned.iter().all(|member| {
            live.iter()
                .any(|live| live.alias == member.alias && live.pub_key == member.public_key)
        })
}

fn pcr_bytes(live: &[u8], pinned: &[u8; SHA384_LEN]) -> bool {
    live == pinned.as_slice()
}

pub(crate) fn verify_boot_proof(
    app_ephemeral_public_key: &[u8],
    boot: &BootProof,
    manifest_digest: &[u8; SHA256_LEN],
    expected: &IdentityPcrs,
    now_ms: u64,
) -> Result<(), TvcError> {
    let decoded = decode_attestation(boot).map_err(|_| TvcError::boot("decode"))?;
    let attestation_ms = validate_shape(&decoded.document).map_err(|_| TvcError::boot("shape"))?;
    assert_fresh(attestation_ms, now_ms).map_err(|_| TvcError::boot("timestamp"))?;
    verify_bindings(
        app_ephemeral_public_key,
        boot,
        &decoded.document,
        manifest_digest,
        expected,
    )
    .map_err(|_| TvcError::boot("bindings"))?;
    verify_aws(
        &decoded.protected,
        &decoded.payload,
        &decoded.signature,
        &decoded.document,
        attestation_ms,
        now_ms,
    )
    .map_err(|_| TvcError::boot("aws-chain"))
}

struct DecodedAttestation {
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
    document: Cbor,
}

fn decode_attestation(boot: &BootProof) -> Result<DecodedAttestation, TvcError> {
    let decoded = decode_cbor(&boot.attestation)?;
    let cose = decoded.as_array()?;
    if cose.len() != COSE_SIGN1_LEN {
        return Err(unverified());
    }
    Ok(DecodedAttestation {
        protected: cose[0].as_bytes()?.to_vec(),
        payload: cose[2].as_bytes()?.to_vec(),
        signature: cose[3].as_bytes()?.to_vec(),
        document: decode_nitro_cbor(cose[2].as_bytes()?)?,
    })
}

fn verify_aws(
    protected: &[u8],
    payload: &[u8],
    signature: &[u8],
    attestation: &Cbor,
    attestation_ms: u64,
    now_ms: u64,
) -> Result<(), TvcError> {
    let certificate = attestation
        .map_get(&CborKey::Text("certificate".into()))?
        .as_bytes()?;
    let bundle = attestation
        .map_get(&CborKey::Text("cabundle".into()))?
        .as_array()?;
    if bundle.is_empty() {
        return Err(unverified());
    }
    let cabundle: Vec<&[u8]> = bundle
        .iter()
        .map(Cbor::as_bytes)
        .collect::<Result<_, _>>()?;
    verify_cose(protected, payload, signature, certificate)?;
    verify_certificate_chain(certificate, &cabundle, attestation_ms, now_ms)
}

fn unverified() -> TvcError {
    TvcError::new(ErrorCode::BootProofUnverified)
}

fn validate_shape(attestation: &Cbor) -> Result<u64, TvcError> {
    let module_id = attestation
        .map_get(&CborKey::Text("module_id".into()))?
        .as_str()?;
    if module_id.is_empty()
        || attestation
            .map_get(&CborKey::Text("digest".into()))?
            .as_str()?
            != "SHA384"
    {
        return Err(unverified());
    }
    let timestamp = attestation
        .map_get(&CborKey::Text("timestamp".into()))?
        .as_i64()?;
    let timestamp = u64::try_from(timestamp)
        .ok()
        .filter(|&ms| ms > 0)
        .ok_or_else(unverified)?;
    match attestation.map_get(&CborKey::Text("nonce".into())) {
        Ok(Cbor::Null) | Err(_) => {}
        Ok(_) => return Err(unverified()),
    }
    let pcrs = attestation
        .map_get(&CborKey::Text("pcrs".into()))?
        .as_map()?;
    if pcrs.len() != PCR_COUNT {
        return Err(unverified());
    }
    for index in 0..PCR_COUNT {
        let bytes = pcr(attestation, i64::try_from(index).map_err(|_| unverified())?)?;
        if bytes.len() != SHA384_LEN {
            return Err(unverified());
        }
    }
    Ok(timestamp)
}

fn assert_fresh(timestamp_ms: u64, now_ms: u64) -> Result<(), TvcError> {
    if now_ms == 0 || timestamp_ms > now_ms.saturating_add(MAX_CLOCK_SKEW_MS) {
        return Err(unverified());
    }
    Ok(())
}

fn verify_bindings(
    app_ephemeral_public_key: &[u8],
    boot: &BootProof,
    attestation: &Cbor,
    manifest_digest: &[u8; SHA256_LEN],
    expected: &IdentityPcrs,
) -> Result<(), TvcError> {
    let manifest = attestation
        .map_get(&CborKey::Text("user_data".into()))?
        .as_bytes()?;
    if manifest != manifest_digest.as_slice() {
        return Err(unverified());
    }
    let attested = attestation
        .map_get(&CborKey::Text("public_key".into()))?
        .as_bytes()?;
    if attested.len() != QOS_P256_PUBLIC_LEN
        || app_ephemeral_public_key != attested
        || boot.ephemeral_public_key.as_slice() != attested
    {
        return Err(unverified());
    }
    let pinned = [expected.pcr0, expected.pcr1, expected.pcr2, expected.pcr3];
    for (index, expected_pcr) in pinned.iter().enumerate() {
        if pcr(attestation, i64::try_from(index).map_err(|_| unverified())?)?
            != expected_pcr.as_slice()
        {
            return Err(unverified());
        }
    }
    if pcr(attestation, PCR17)? != live_manifest_pcr(manifest, attested).as_slice() {
        return Err(unverified());
    }
    Ok(())
}

fn pcr(attestation: &Cbor, index: i64) -> Result<&[u8], TvcError> {
    attestation
        .map_get(&CborKey::Text("pcrs".into()))?
        .map_get(&CborKey::Int(index))?
        .as_bytes()
}

fn live_manifest_pcr(manifest: &[u8], ephemeral: &[u8]) -> [u8; SHA384_LEN] {
    let preimage = format!(
        "{{\"domain\":\"{LIVE_MANIFEST_DOMAIN}\",\"ephemeralPublicKey\":\"{}\",\"manifestHash\":\"{}\"}}",
        encode_lower_hex(ephemeral),
        encode_lower_hex(manifest),
    );
    let commitment = Sha384::digest(preimage.as_bytes());
    Sha384::new()
        .chain_update([0u8; SHA384_LEN])
        .chain_update(commitment)
        .finalize()
        .into()
}

fn verify_cose(
    protected: &[u8],
    payload: &[u8],
    signature: &[u8],
    certificate: &[u8],
) -> Result<(), TvcError> {
    let header = decode_cbor(protected)?;
    if header.map_get(&CborKey::Int(COSE_HEADER_ALG))?.as_i64()? != COSE_ALG_ES384 {
        return Err(unverified());
    }
    let leaf = Certificate::from_der(certificate).map_err(|_| unverified())?;
    let spki_der = leaf
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| unverified())?;
    let key = VerifyingKey::from_public_key_der(&spki_der).map_err(|_| unverified())?;
    let signature = Signature::from_slice(signature).map_err(|_| unverified())?;
    let signed = encode_cose_sig_structure(protected, payload);
    key.verify(&signed, &signature).map_err(|_| unverified())
}

fn verify_certificate_chain(
    leaf: &[u8],
    cabundle: &[impl AsRef<[u8]>],
    attestation_ms: u64,
    now_ms: u64,
) -> Result<(), TvcError> {
    let root_der = pinned_root_der()?;
    verify_certificate_chain_against_root(leaf, cabundle, root_der, attestation_ms, now_ms)
}

fn verify_certificate_chain_against_root(
    leaf: &[u8],
    cabundle: &[impl AsRef<[u8]>],
    root_der: &[u8],
    attestation_ms: u64,
    now_ms: u64,
) -> Result<(), TvcError> {
    let root = Certificate::from_der(root_der).map_err(|_| unverified())?;
    assert_cert_valid_at(&root, now_ms)?;
    assert_cert_valid_at(&root, attestation_ms)?;

    let root_cert_der = CertificateDer::from(root_der);
    let anchor = anchor_from_trusted_cert(&root_cert_der).map_err(|_| unverified())?;
    let leaf_cert_der = CertificateDer::from(leaf);
    let end_entity = EndEntityCert::try_from(&leaf_cert_der).map_err(|_| unverified())?;
    // cabundle[0] is an untrusted copy of the root; pass only intermediates to webpki.
    let mut intermediates = Vec::with_capacity(cabundle.len().saturating_sub(1));
    for der in cabundle.iter().skip(1) {
        let der = der.as_ref();
        // webpki does not enforce KeyUsage.keyCertSign on intermediates; check it when present.
        assert_key_cert_sign_if_present(der)?;
        intermediates.push(CertificateDer::from(der));
    }
    // Validate leaf and intermediate lifetimes at the attestation timestamp:
    // enclaves outlive the 3-hour Nitro leaf cert, so `now_ms` applies only to the root.
    let validation_time = UnixTime::since_unix_epoch(Duration::from_secs(
        Duration::from_millis(attestation_ms).as_secs(),
    ));
    end_entity
        .verify_for_usage(
            &[webpki::ring::ECDSA_P384_SHA384],
            &[anchor],
            &intermediates,
            validation_time,
            KeyUsage::server_auth(),
            None,
            None,
        )
        .map(|_| ())
        .map_err(|_| unverified())
}

fn assert_key_cert_sign_if_present(der: &[u8]) -> Result<(), TvcError> {
    let cert = Certificate::from_der(der).map_err(|_| unverified())?;
    for ext in cert.tbs_certificate.extensions.as_deref().unwrap_or(&[]) {
        if ext.extn_id == X509KeyUsage::OID {
            let usage =
                X509KeyUsage::from_der(ext.extn_value.as_bytes()).map_err(|_| unverified())?;
            if !usage.0.contains(KeyUsages::KeyCertSign) {
                return Err(unverified());
            }
        }
    }
    Ok(())
}

fn assert_cert_valid_at(cert: &Certificate, time_ms: u64) -> Result<(), TvcError> {
    let at = UNIX_EPOCH
        .checked_add(Duration::from_millis(time_ms))
        .ok_or_else(unverified)?;
    let validity = &cert.tbs_certificate.validity;
    if at < validity.not_before.to_system_time() || at > validity.not_after.to_system_time() {
        return Err(unverified());
    }
    Ok(())
}

fn pinned_root_der() -> Result<&'static [u8], TvcError> {
    static ROOT_DER: OnceLock<Result<Vec<u8>, ()>> = OnceLock::new();
    ROOT_DER
        .get_or_init(|| {
            let (label, der) =
                x509_cert::der::pem::decode_vec(AWS_NITRO_ROOT_PEM.as_bytes()).map_err(|_| ())?;
            if label != PEM_CERT_LABEL || encode_lower_hex(&Sha256::digest(&der)) != AWS_ROOT_SHA256
            {
                return Err(());
            }
            Ok(der)
        })
        .as_deref()
        .map_err(|_| unverified())
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "../tests/unit/attestation.rs"]
mod tests;
