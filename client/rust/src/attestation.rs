//! Boot Proof checks beyond Turnkey's combined verifier.
//!
//! This module checks the COSE signature, the Nitro certificate chain,
//! PCR0–3, PCR17, the manifest the pinned set approved, the replica key, and
//! freshness. Turnkey's `verify` skips the image pins and expects a
//! `timestampMs` field these proofs do not carry.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256, Sha384};
use spr_tvc_wire::encoding::encode_lower_hex;
use spr_tvc_wire::error::{ErrorCode, TvcError};
use spr_tvc_wire::types::ReleasePolicy;
use x509_cert::der::oid::{AssociatedOid, ObjectIdentifier};
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
use x509_cert::Certificate;

use crate::cbor::{decode_cbor, decode_nitro_cbor, encode_cose_sig_structure, Cbor, CborKey};

const MAX_CLOCK_SKEW_MS: u64 = 60_000;
const PCR_LEN: usize = 48;
const PCR_COUNT: i64 = 32;
const EPHEMERAL_PUBLIC_KEY_LEN: usize = 130;
const PCR17: i64 = 17;
const COSE_HEADER_ALG: i64 = 1;
const COSE_ALG_ES384: i64 = -35;
const OID_ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const LIVE_MANIFEST_DOMAIN: &str = "qos-live-manifest-pcr-commitment-v1";
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

/// PCR0–3 for the expected QOS deployment. Never taken from the enclave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityPcrs {
    pub pcr0: [u8; PCR_LEN],
    pub pcr1: [u8; PCR_LEN],
    pub pcr2: [u8; PCR_LEN],
    pub pcr3: [u8; PCR_LEN],
}

/// The attestation document and the ephemeral key the Boot Proof names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootProof {
    pub attestation: Vec<u8>,
    pub ephemeral_public_key: [u8; EPHEMERAL_PUBLIC_KEY_LEN],
    /// QOS manifest envelope. Empty on the synthetic documents the chain tests build.
    pub manifest_envelope: Vec<u8>,
}

/// The manifest hash when the pinned manifest set approved this envelope.
pub(crate) fn approved_manifest_digest(
    envelope: &[u8],
    policy: &ReleasePolicy,
    pcrs: &IdentityPcrs,
) -> Result<[u8; 32], TvcError> {
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

fn pcr_bytes(live: &[u8], pinned: &[u8; PCR_LEN]) -> bool {
    live == pinned.as_slice()
}

pub(crate) fn verify_boot_proof(
    app_ephemeral_public_key: &[u8],
    boot: &BootProof,
    manifest_digest: &[u8; 32],
    expected: &IdentityPcrs,
    now_ms: u64,
) -> Result<(), TvcError> {
    let decoded = decode_attestation(boot).map_err(|_| TvcError::boot("decode"))?;
    validate_shape(&decoded.document).map_err(|_| TvcError::boot("shape"))?;
    assert_fresh(&decoded.document, now_ms).map_err(|_| TvcError::boot("timestamp"))?;
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
    if cose.len() != 4 {
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
    now_ms: u64,
) -> Result<(), TvcError> {
    let attestation_ms = u64::try_from(
        attestation
            .map_get(&CborKey::Text("timestamp".into()))?
            .as_i64()?,
    )
    .map_err(|_| unverified())?;
    let certificate = attestation
        .map_get(&CborKey::Text("certificate".into()))?
        .as_bytes()?;
    let bundle = attestation
        .map_get(&CborKey::Text("cabundle".into()))?
        .as_array()?;
    if bundle.is_empty() {
        return Err(unverified());
    }
    let cabundle = bundle
        .iter()
        .map(|item| item.as_bytes().map(ToOwned::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    verify_cose(protected, payload, signature, certificate)?;
    verify_certificate_chain(certificate, &cabundle, attestation_ms, now_ms)
}

fn unverified() -> TvcError {
    TvcError::new(ErrorCode::BootProofUnverified)
}

fn validate_shape(attestation: &Cbor) -> Result<(), TvcError> {
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
    if timestamp <= 0 {
        return Err(unverified());
    }
    match attestation.map_get(&CborKey::Text("nonce".into())) {
        Ok(Cbor::Null) | Err(_) => {}
        Ok(_) => return Err(unverified()),
    }
    let pcrs = attestation
        .map_get(&CborKey::Text("pcrs".into()))?
        .as_map()?;
    if pcrs.len() != usize::try_from(PCR_COUNT).map_err(|_| unverified())? {
        return Err(unverified());
    }
    for index in 0..PCR_COUNT {
        let bytes = pcr(attestation, index)?;
        if bytes.len() != PCR_LEN {
            return Err(unverified());
        }
    }
    Ok(())
}

fn assert_fresh(attestation: &Cbor, now_ms: u64) -> Result<(), TvcError> {
    if now_ms == 0 {
        return Err(unverified());
    }
    let timestamp = u64::try_from(
        attestation
            .map_get(&CborKey::Text("timestamp".into()))?
            .as_i64()?,
    )
    .map_err(|_| unverified())?;
    if timestamp > now_ms.saturating_add(MAX_CLOCK_SKEW_MS) {
        return Err(unverified());
    }
    Ok(())
}

fn verify_bindings(
    app_ephemeral_public_key: &[u8],
    boot: &BootProof,
    attestation: &Cbor,
    manifest_digest: &[u8; 32],
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
    if attested.len() != EPHEMERAL_PUBLIC_KEY_LEN
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
    if pcr(attestation, PCR17)? != live_manifest_pcr(manifest, attested)?.as_slice() {
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

fn live_manifest_pcr(manifest: &[u8], ephemeral: &[u8]) -> Result<[u8; PCR_LEN], TvcError> {
    let preimage = format!(
        "{{\"domain\":\"{LIVE_MANIFEST_DOMAIN}\",\"ephemeralPublicKey\":\"{}\",\"manifestHash\":\"{}\"}}",
        encode_lower_hex(ephemeral),
        encode_lower_hex(manifest),
    );
    let commitment = Sha384::digest(preimage.as_bytes());
    let mut extension = [0u8; 96];
    extension[48..].copy_from_slice(&commitment);
    let digest = Sha384::digest(extension);
    let mut pcr = [0u8; PCR_LEN];
    pcr.copy_from_slice(&digest);
    Ok(pcr)
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
    let key = p384_key(&leaf)?;
    let signature = Signature::from_slice(signature).map_err(|_| unverified())?;
    let signed = encode_cose_sig_structure(protected, payload);
    key.verify(&signed, &signature).map_err(|_| unverified())
}

fn verify_certificate_chain(
    leaf: &[u8],
    cabundle: &[Vec<u8>],
    attestation_ms: u64,
    now_ms: u64,
) -> Result<(), TvcError> {
    let root_der = pinned_root_der()?;
    if hex::encode(Sha256::digest(&root_der)) != AWS_ROOT_SHA256 {
        return Err(unverified());
    }
    let root = Certificate::from_der(&root_der).map_err(|_| unverified())?;
    verify_certificate_chain_against_root(leaf, cabundle, &root, &root_der, attestation_ms, now_ms)
}

fn verify_certificate_chain_against_root(
    leaf: &[u8],
    cabundle: &[Vec<u8>],
    root: &Certificate,
    root_der: &[u8],
    attestation_ms: u64,
    now_ms: u64,
) -> Result<(), TvcError> {
    assert_ca_cert(root)?;
    if root.tbs_certificate.issuer != root.tbs_certificate.subject {
        return Err(unverified());
    }
    verify_cert(root, root)?;
    assert_cert_valid_at(root, now_ms)?;
    assert_cert_valid_at(root, attestation_ms)?;
    // The bundle's first certificate is an untrusted copy of the root.
    let mut issuers = Vec::with_capacity(cabundle.len());
    for der in cabundle.iter().skip(1) {
        issuers.push((
            Certificate::from_der(der).map_err(|_| unverified())?,
            der.clone(),
        ));
    }
    issuers.push((root.clone(), root_der.to_vec()));
    let mut current = Certificate::from_der(leaf).map_err(|_| unverified())?;
    // Validate leaf and intermediate lifetimes at the attestation timestamp:
    // enclaves outlive the 3-hour Nitro leaf cert, so `now_ms` applies only to the root.
    assert_cert_valid_at(&current, attestation_ms)?;
    let mut hops = 1usize;
    let expected = cabundle.len() + 1;
    while hops < expected {
        let issuer_index = issuers
            .iter()
            .position(|(issuer, _)| {
                current.tbs_certificate.issuer == issuer.tbs_certificate.subject
                    && assert_ca_cert(issuer).is_ok()
                    && assert_cert_valid_at(issuer, attestation_ms).is_ok()
                    && verify_cert(&current, issuer).is_ok()
            })
            .ok_or_else(unverified)?;
        let (issuer, issuer_der) = issuers.remove(issuer_index);
        hops += 1;
        if issuer_der == root_der {
            return if hops == expected && issuers.is_empty() {
                Ok(())
            } else {
                Err(unverified())
            };
        }
        current = issuer;
    }
    Err(unverified())
}

fn assert_ca_cert(cert: &Certificate) -> Result<(), TvcError> {
    let extensions = cert
        .tbs_certificate
        .extensions
        .as_deref()
        .ok_or_else(unverified)?;
    let mut basic_ca = false;
    for ext in extensions {
        if ext.extn_id == BasicConstraints::OID {
            let bc =
                BasicConstraints::from_der(ext.extn_value.as_bytes()).map_err(|_| unverified())?;
            if !bc.ca {
                return Err(unverified());
            }
            basic_ca = true;
        } else if ext.extn_id == KeyUsage::OID {
            let usage = KeyUsage::from_der(ext.extn_value.as_bytes()).map_err(|_| unverified())?;
            if !usage.0.contains(KeyUsages::KeyCertSign) {
                return Err(unverified());
            }
        }
    }
    if !basic_ca {
        return Err(unverified());
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

fn verify_cert(subject: &Certificate, issuer: &Certificate) -> Result<(), TvcError> {
    if subject.signature_algorithm.oid != OID_ECDSA_WITH_SHA384
        || subject.tbs_certificate.signature != subject.signature_algorithm
    {
        return Err(unverified());
    }
    let key = p384_key(issuer)?;
    let signature = Signature::from_der(subject.signature.as_bytes().ok_or_else(unverified)?)
        .map_err(|_| unverified())?;
    let tbs = subject.tbs_certificate.to_der().map_err(|_| unverified())?;
    key.verify(&tbs, &signature).map_err(|_| unverified())
}

fn p384_key(cert: &Certificate) -> Result<VerifyingKey, TvcError> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        return Err(unverified());
    }
    let curve: ObjectIdentifier = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(unverified)?
        .decode_as()
        .map_err(|_| unverified())?;
    if curve != OID_SECP384R1 {
        return Err(unverified());
    }
    let raw = spki.subject_public_key.raw_bytes();
    VerifyingKey::from_sec1_bytes(raw).map_err(|_| unverified())
}

fn pinned_root_der() -> Result<Vec<u8>, TvcError> {
    let body: String = AWS_NITRO_ROOT_PEM
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| unverified())
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClientError;

    #[test]
    fn pinned_aws_root_matches_the_fingerprint_and_signs_itself() {
        let der = pinned_root_der().unwrap();
        assert_eq!(hex::encode(Sha256::digest(&der)), AWS_ROOT_SHA256);
        let root = Certificate::from_der(&der).unwrap();
        assert_ca_cert(&root).unwrap();
        verify_cert(&root, &root).unwrap();
        assert_cert_valid_at(&root, 1_700_000_000_000).unwrap();
        assert!(assert_cert_valid_at(&root, 1_000_000_000_000).is_err());
        assert!(assert_cert_valid_at(&root, 2_524_608_000_000).is_err());
    }

    #[test]
    fn wrong_pcr_fails_before_the_certificate_chain() {
        let manifest = [0x11; 32];
        let ephemeral = [0x04; EPHEMERAL_PUBLIC_KEY_LEN];
        let proof = synthetic_boot(&manifest, &ephemeral, &[0; PCR_LEN]);
        let error = verify_boot_proof(
            &ephemeral,
            &proof,
            &manifest,
            &IdentityPcrs {
                pcr0: [0xff; PCR_LEN],
                pcr1: [0; PCR_LEN],
                pcr2: [0; PCR_LEN],
                pcr3: [0; PCR_LEN],
            },
            1_000_000,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::BootProofUnverified);
        assert_eq!(error.detail, Some("bindings"));
        assert_eq!(error.to_string(), "BootProofUnverified");
        assert_eq!(
            ClientError::from(error).to_string(),
            "BootProofUnverified: bindings"
        );
    }

    #[test]
    fn unchained_attestation_is_rejected() {
        let manifest = [0x11; 32];
        let ephemeral = [0x04; EPHEMERAL_PUBLIC_KEY_LEN];
        let pcr0 = [0x22; PCR_LEN];
        let proof = synthetic_boot(&manifest, &ephemeral, &pcr0);
        let error = verify_boot_proof(
            &ephemeral,
            &proof,
            &manifest,
            &IdentityPcrs {
                pcr0,
                pcr1: [0; PCR_LEN],
                pcr2: [0; PCR_LEN],
                pcr3: [0; PCR_LEN],
            },
            1_000_000,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::BootProofUnverified);
        assert_eq!(error.detail, Some("aws-chain"));
        assert_eq!(
            ClientError::from(error).to_string(),
            "BootProofUnverified: aws-chain"
        );
    }

    #[test]
    fn a_boot_proof_that_does_not_decode_names_that_stage() {
        let error = verify_boot_proof(
            &[0x04; EPHEMERAL_PUBLIC_KEY_LEN],
            &BootProof {
                attestation: Vec::new(),
                ephemeral_public_key: [0x04; EPHEMERAL_PUBLIC_KEY_LEN],
                manifest_envelope: Vec::new(),
            },
            &[0x11; 32],
            &IdentityPcrs {
                pcr0: [0; PCR_LEN],
                pcr1: [0; PCR_LEN],
                pcr2: [0; PCR_LEN],
                pcr3: [0; PCR_LEN],
            },
            1_000_000,
        )
        .unwrap_err();
        assert_eq!(error.detail, Some("decode"));
    }

    #[test]
    fn a_non_sha384_digest_is_the_shape_stage() {
        let manifest = [0x11; 32];
        let ephemeral = [0x04; EPHEMERAL_PUBLIC_KEY_LEN];
        let pcr0 = [0x22; PCR_LEN];
        let mut proof = synthetic_boot(&manifest, &ephemeral, &pcr0);
        let digest = b"SHA384";
        let offset = proof
            .attestation
            .windows(digest.len())
            .position(|window| window == digest)
            .unwrap();
        proof.attestation[offset..offset + digest.len()].copy_from_slice(b"SHA256");
        let error = verify_boot_proof(
            &ephemeral,
            &proof,
            &manifest,
            &IdentityPcrs {
                pcr0,
                pcr1: [0; PCR_LEN],
                pcr2: [0; PCR_LEN],
                pcr3: [0; PCR_LEN],
            },
            1_000_000,
        )
        .unwrap_err();
        assert_eq!(error.detail, Some("shape"));
    }

    #[test]
    fn a_clock_reading_of_zero_is_the_timestamp_stage() {
        let manifest = [0x11; 32];
        let ephemeral = [0x04; EPHEMERAL_PUBLIC_KEY_LEN];
        let pcr0 = [0x22; PCR_LEN];
        let error = verify_boot_proof(
            &ephemeral,
            &synthetic_boot(&manifest, &ephemeral, &pcr0),
            &manifest,
            &IdentityPcrs {
                pcr0,
                pcr1: [0; PCR_LEN],
                pcr2: [0; PCR_LEN],
                pcr3: [0; PCR_LEN],
            },
            0,
        )
        .unwrap_err();
        assert_eq!(error.detail, Some("timestamp"));
    }

    #[test]
    fn the_pinned_manifest_set_approves_the_boot_manifest() {
        use qos_core::protocol::services::boot::manifest::{
            canonical_json_hash, VersionedManifestEnvelope,
        };
        use spr_tvc_wire::constants::{API_VERSION, EXPECTED_TURNKEY_TRUST_ROOT_ID};
        use spr_tvc_wire::types::{ManifestSetMember, ManifestSetPolicy, Network, ReleasePolicy};

        let bytes = include_bytes!(
            "../../../decryption-service/tests/fixtures/qos-0.12.1-manifest-envelope.json"
        );
        let versioned = VersionedManifestEnvelope::try_from_slice_compat(bytes).unwrap();
        let VersionedManifestEnvelope::V2(envelope) = &versioned else {
            panic!("fixture envelope is v2");
        };
        let manifest = &envelope.manifest;
        let pcr = |bytes: &[u8]| -> [u8; PCR_LEN] { bytes.try_into().unwrap() };
        let pcrs = IdentityPcrs {
            pcr0: pcr(&manifest.enclave.pcr0),
            pcr1: pcr(&manifest.enclave.pcr1),
            pcr2: pcr(&manifest.enclave.pcr2),
            pcr3: pcr(&manifest.enclave.pcr3),
        };
        let policy = ReleasePolicy {
            version: API_VERSION,
            network: Network::Devnet,
            security_domain_id: [0; 32],
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
            minimum_manifest_nonce: 0,
            quorum_key_id: "quorum".into(),
            quorum_key_epoch: 1,
            quorum_public_key: manifest.namespace.quorum_key.clone(),
            allowed_operations: Vec::new(),
            max_encrypted_request_bytes: 1,
            max_encrypted_response_bytes: 1,
            turnkey_trust_root_id: EXPECTED_TURNKEY_TRUST_ROOT_ID.into(),
            valid_from_ms: 0,
            expires_at_ms: 1,
            revocation_epoch: 0,
        };
        let digest = approved_manifest_digest(bytes, &policy, &pcrs).unwrap();
        assert_eq!(digest, canonical_json_hash(manifest));

        let mut foreign = policy.clone();
        foreign.manifest_set.members[0].alias = "someone-else".into();
        let error = approved_manifest_digest(bytes, &foreign, &pcrs).unwrap_err();
        assert_eq!(error.detail, Some("manifest"));

        let mut raised = policy.clone();
        raised.minimum_manifest_nonce = u64::from(manifest.namespace.nonce) + 1;
        assert_eq!(
            approved_manifest_digest(bytes, &raised, &pcrs)
                .unwrap_err()
                .detail,
            Some("manifest")
        );

        let mut parsed: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        parsed["manifest"]["namespace"]["name"] = serde_json::json!("other-namespace");
        let mutated = serde_json::to_vec(&parsed).unwrap();
        assert_eq!(
            approved_manifest_digest(&mutated, &policy, &pcrs)
                .unwrap_err()
                .detail,
            Some("manifest")
        );

        parsed["manifest"]["namespace"]["name"] =
            serde_json::json!(manifest.namespace.name.clone());
        parsed["manifest"]["pivot"]["debugMode"] = serde_json::json!(true);
        let debug = serde_json::to_vec(&parsed).unwrap();
        assert_eq!(
            approved_manifest_digest(&debug, &policy, &pcrs)
                .unwrap_err()
                .detail,
            Some("manifest")
        );

        parsed["manifest"]["pivot"]["debugMode"] = serde_json::json!(false);
        parsed["manifestSetApprovals"] = serde_json::json!([]);
        let missing = serde_json::to_vec(&parsed).unwrap();
        assert_eq!(
            approved_manifest_digest(&missing, &policy, &pcrs)
                .unwrap_err()
                .detail,
            Some("manifest")
        );
    }

    #[test]
    fn x509_chain_checks_ca_constraints_dn_validity_and_cose_alg() {
        use p384::ecdsa::signature::Signer;
        use p384::ecdsa::SigningKey;
        use x509_cert::der::asn1::{BitString, OctetString};
        use x509_cert::der::Any;
        use x509_cert::ext::Extension;
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
        use x509_cert::time::{Time, Validity};
        use x509_cert::TbsCertificate;

        struct TestCert<'a> {
            subject_cn: &'a str,
            issuer_cn: &'a str,
            subject_key: &'a SigningKey,
            issuer_key: &'a SigningKey,
            validity: (u64, u64),
            basic_ca: Option<bool>,
            key_cert_sign: Option<bool>,
        }

        impl TestCert<'_> {
            fn build(self) -> Vec<u8> {
                let (not_before_secs, not_after_secs) = self.validity;
                let alg = AlgorithmIdentifierOwned {
                    oid: OID_ECDSA_WITH_SHA384,
                    parameters: None,
                };
                let pub_bytes = self.subject_key.verifying_key().to_encoded_point(false);
                let spki = SubjectPublicKeyInfoOwned {
                    algorithm: AlgorithmIdentifierOwned {
                        oid: OID_EC_PUBLIC_KEY,
                        parameters: Some(Any::encode_from(&OID_SECP384R1).unwrap()),
                    },
                    subject_public_key: BitString::from_bytes(pub_bytes.as_bytes()).unwrap(),
                };
                let mut exts = Vec::new();
                if let Some(ca) = self.basic_ca {
                    exts.push(Extension {
                        extn_id: BasicConstraints::OID,
                        critical: true,
                        extn_value: OctetString::new(
                            BasicConstraints {
                                ca,
                                path_len_constraint: None,
                            }
                            .to_der()
                            .unwrap(),
                        )
                        .unwrap(),
                    });
                }
                if let Some(cert_sign) = self.key_cert_sign {
                    let flags = if cert_sign {
                        KeyUsages::KeyCertSign | KeyUsages::CRLSign
                    } else {
                        KeyUsages::DigitalSignature.into()
                    };
                    exts.push(Extension {
                        extn_id: KeyUsage::OID,
                        critical: true,
                        extn_value: OctetString::new(KeyUsage(flags).to_der().unwrap()).unwrap(),
                    });
                }
                let tbs = TbsCertificate {
                    version: x509_cert::Version::V3,
                    serial_number: SerialNumber::from(1u8),
                    signature: alg.clone(),
                    issuer: Name::from_str(&format!("CN={}", self.issuer_cn)).unwrap(),
                    validity: Validity {
                        not_before: Time::try_from(
                            UNIX_EPOCH + Duration::from_secs(not_before_secs),
                        )
                        .unwrap(),
                        not_after: Time::try_from(UNIX_EPOCH + Duration::from_secs(not_after_secs))
                            .unwrap(),
                    },
                    subject: Name::from_str(&format!("CN={}", self.subject_cn)).unwrap(),
                    subject_public_key_info: spki,
                    issuer_unique_id: None,
                    subject_unique_id: None,
                    extensions: (!exts.is_empty()).then_some(exts),
                };
                let tbs_der = tbs.to_der().unwrap();
                let sig: p384::ecdsa::DerSignature = self.issuer_key.sign(&tbs_der);
                Certificate {
                    tbs_certificate: tbs,
                    signature_algorithm: alg,
                    signature: BitString::from_bytes(sig.as_bytes()).unwrap(),
                }
                .to_der()
                .unwrap()
            }
        }

        use std::str::FromStr;

        let root_key = SigningKey::from_slice(&[1u8; 48]).unwrap();
        let inter_key = SigningKey::from_slice(&[2u8; 48]).unwrap();
        let leaf_key = SigningKey::from_slice(&[3u8; 48]).unwrap();

        let att_secs = 1_750_000_000u64;
        let att_ms = att_secs * 1_000;
        let later_ms = (att_secs + 86_400) * 1_000; // 24h after boot; leaf expired, root still valid

        let root_der = TestCert {
            subject_cn: "root",
            issuer_cn: "root",
            subject_key: &root_key,
            issuer_key: &root_key,
            validity: (att_secs - 86_400, att_secs + 10 * 86_400),
            basic_ca: Some(true),
            key_cert_sign: Some(true),
        }
        .build();
        let root = Certificate::from_der(&root_der).unwrap();
        let inter_der = TestCert {
            subject_cn: "inter",
            issuer_cn: "root",
            subject_key: &inter_key,
            issuer_key: &root_key,
            validity: (att_secs - 3_600, att_secs + 7_200),
            basic_ca: Some(true),
            key_cert_sign: Some(true),
        }
        .build();
        let leaf_der = TestCert {
            subject_cn: "leaf",
            issuer_cn: "inter",
            subject_key: &leaf_key,
            issuer_key: &inter_key,
            validity: (att_secs - 60, att_secs + 10_800),
            basic_ca: Some(false),
            key_cert_sign: Some(false),
        }
        .build();

        // Valid chain passes both at boot and 24h later when the enclave is still running.
        verify_certificate_chain_against_root(
            &leaf_der,
            &[root_der.clone(), inter_der.clone()],
            &root,
            &root_der,
            att_ms,
            att_ms,
        )
        .unwrap();
        verify_certificate_chain_against_root(
            &leaf_der,
            &[root_der.clone(), inter_der.clone()],
            &root,
            &root_der,
            att_ms,
            later_ms,
        )
        .unwrap();

        // Expired leaf at attestation timestamp is rejected.
        let expired_leaf = TestCert {
            subject_cn: "leaf",
            issuer_cn: "inter",
            subject_key: &leaf_key,
            issuer_key: &inter_key,
            validity: (att_secs - 7_200, att_secs - 1),
            basic_ca: Some(false),
            key_cert_sign: Some(false),
        }
        .build();
        assert!(verify_certificate_chain_against_root(
            &expired_leaf,
            &[root_der.clone(), inter_der.clone()],
            &root,
            &root_der,
            att_ms,
            att_ms,
        )
        .is_err());

        // Non-CA intermediate is rejected.
        let non_ca_inter = TestCert {
            subject_cn: "inter",
            issuer_cn: "root",
            subject_key: &inter_key,
            issuer_key: &root_key,
            validity: (att_secs - 3_600, att_secs + 7_200),
            basic_ca: Some(false),
            key_cert_sign: Some(true),
        }
        .build();
        assert!(verify_certificate_chain_against_root(
            &leaf_der,
            &[root_der.clone(), non_ca_inter],
            &root,
            &root_der,
            att_ms,
            att_ms,
        )
        .is_err());

        // Intermediate without keyCertSign is rejected.
        let no_cert_sign_inter = TestCert {
            subject_cn: "inter",
            issuer_cn: "root",
            subject_key: &inter_key,
            issuer_key: &root_key,
            validity: (att_secs - 3_600, att_secs + 7_200),
            basic_ca: Some(true),
            key_cert_sign: Some(false),
        }
        .build();
        assert!(verify_certificate_chain_against_root(
            &leaf_der,
            &[root_der.clone(), no_cert_sign_inter],
            &root,
            &root_der,
            att_ms,
            att_ms,
        )
        .is_err());

        // Mismatched Issuer/Subject DN is rejected even with valid signature.
        let wrong_dn_leaf = TestCert {
            subject_cn: "leaf",
            issuer_cn: "wrong-issuer",
            subject_key: &leaf_key,
            issuer_key: &inter_key,
            validity: (att_secs - 60, att_secs + 10_800),
            basic_ca: Some(false),
            key_cert_sign: Some(false),
        }
        .build();
        assert!(verify_certificate_chain_against_root(
            &wrong_dn_leaf,
            &[root_der.clone(), inter_der],
            &root,
            &root_der,
            att_ms,
            att_ms,
        )
        .is_err());

        // COSE_Sign1 verifies ES384 protected header and rejects wrong algorithm.
        let protected_es384 = [0xa1, 0x01, 0x38, 0x22];
        let payload = b"attestation";
        let sig: Signature = leaf_key.sign(&encode_cose_sig_structure(&protected_es384, payload));
        verify_cose(&protected_es384, payload, &sig.to_bytes(), &leaf_der).unwrap();

        let protected_es256 = [0xa1, 0x01, 0x26]; // {1: -7}
        let wrong_alg_sig: Signature =
            leaf_key.sign(&encode_cose_sig_structure(&protected_es256, payload));
        assert!(verify_cose(
            &protected_es256,
            payload,
            &wrong_alg_sig.to_bytes(),
            &leaf_der
        )
        .is_err());
    }

    fn synthetic_boot(
        manifest: &[u8; 32],
        ephemeral: &[u8; EPHEMERAL_PUBLIC_KEY_LEN],
        pcr0: &[u8; PCR_LEN],
    ) -> BootProof {
        let live = live_manifest_pcr(manifest, ephemeral).unwrap();
        let zeros = [0u8; PCR_LEN];
        let mut pcr_body = Vec::new();
        for index in 0..PCR_COUNT {
            let value = if index == 0 {
                pcr0.as_slice()
            } else if index == PCR17 {
                live.as_slice()
            } else {
                zeros.as_slice()
            };
            pcr_body.extend(cbor_unsigned(index as u64));
            pcr_body.extend(cbor_bytes(value));
        }
        let mut fields = Vec::new();
        for (name, value) in [
            ("module_id", cbor_text("enclave")),
            ("digest", cbor_text("SHA384")),
            ("timestamp", cbor_unsigned(1_000)),
            ("nonce", vec![0xf6]),
            ("pcrs", cbor_container(5, PCR_COUNT as u64, pcr_body)),
            ("user_data", cbor_bytes(manifest)),
            ("public_key", cbor_bytes(ephemeral)),
            ("certificate", cbor_bytes(&[0])),
            ("cabundle", cbor_container(4, 1, cbor_bytes(&[0]))),
        ] {
            fields.extend(cbor_text(name));
            fields.extend(value);
        }
        let payload = cbor_container(5, 9, fields);
        let cose = cbor_container(
            4,
            4,
            [
                cbor_bytes(&[0xa1, 0x01, 0x38, 0x22]),
                cbor_container(5, 0, Vec::new()),
                cbor_bytes(&payload),
                cbor_bytes(&[0]),
            ]
            .concat(),
        );
        BootProof {
            attestation: [vec![0xd2], cose].concat(),
            ephemeral_public_key: *ephemeral,
            manifest_envelope: Vec::new(),
        }
    }

    fn cbor_unsigned(value: u64) -> Vec<u8> {
        if value < 24 {
            return vec![value as u8];
        }
        if value < 0x100 {
            return vec![24, value as u8];
        }
        vec![25, (value >> 8) as u8, value as u8]
    }

    fn cbor_bytes(bytes: &[u8]) -> Vec<u8> {
        let mut out = cbor_head(2, bytes.len() as u64);
        out.extend_from_slice(bytes);
        out
    }

    fn cbor_text(text: &str) -> Vec<u8> {
        let mut out = cbor_head(3, text.len() as u64);
        out.extend_from_slice(text.as_bytes());
        out
    }

    fn cbor_container(major: u8, len: u64, body: Vec<u8>) -> Vec<u8> {
        let mut out = cbor_head(major, len);
        out.extend(body);
        out
    }

    fn cbor_head(major: u8, argument: u64) -> Vec<u8> {
        let prefix = major << 5;
        if argument < 24 {
            return vec![prefix | argument as u8];
        }
        if argument < 0x100 {
            return vec![prefix | 24, argument as u8];
        }
        vec![prefix | 25, (argument >> 8) as u8, argument as u8]
    }
}
