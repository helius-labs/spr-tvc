//! Boot Proof checks that Turnkey's combined verifier does not make.
//!
//! The COSE signature and the Nitro certificate chain are checked here, then
//! PCR0–3, PCR17, the manifest allowlist, the replica key, and freshness.
//! Turnkey's `verify` skips the image pins and expects a `timestampMs` field
//! these proofs do not carry.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256, Sha384};
use spr_tvc_protocol::encoding::{decode_lower_hex, encode_lower_hex};
use spr_tvc_protocol::error::{ErrorCode, TvcError};
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

use crate::cbor::{decode_cbor, decode_nitro_cbor, encode_cose_sig_structure, Cbor, CborKey};

const MAX_CLOCK_SKEW_MS: u64 = 60_000;
const PCR_LEN: usize = 48;
const PCR_COUNT: i64 = 32;
const EPHEMERAL_PUBLIC_KEY_LEN: usize = 130;
const PCR17: i64 = 17;
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
}

pub(crate) fn verify_boot_proof(
    app_ephemeral_public_key: &[u8],
    boot: &BootProof,
    allowed_manifests: &[String],
    expected: &IdentityPcrs,
    now_ms: u64,
) -> Result<(), TvcError> {
    let decoded = decode_cbor(&boot.attestation)?;
    let cose = decoded.as_array()?;
    if cose.len() != 4 {
        return Err(unverified());
    }
    let protected = cose[0].as_bytes()?.to_vec();
    let payload = cose[2].as_bytes()?.to_vec();
    let signature = cose[3].as_bytes()?.to_vec();
    let attestation = decode_nitro_cbor(&payload)?;
    validate_shape(&attestation)?;
    assert_fresh(&attestation, now_ms)?;
    verify_bindings(
        app_ephemeral_public_key,
        boot,
        &attestation,
        allowed_manifests,
        expected,
    )?;
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
    verify_cose(&protected, &payload, &signature, certificate)?;
    verify_certificate_chain(certificate, &cabundle, now_ms)
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
    allowed_manifests: &[String],
    expected: &IdentityPcrs,
) -> Result<(), TvcError> {
    if allowed_manifests.is_empty() {
        return Err(unverified());
    }
    let manifest = attestation
        .map_get(&CborKey::Text("user_data".into()))?
        .as_bytes()?;
    if manifest.len() != 32
        || !allowed_manifests
            .iter()
            .any(|digest| decode_lower_hex(digest).ok().as_deref() == Some(manifest))
    {
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
    let leaf = Certificate::from_der(certificate).map_err(|_| unverified())?;
    let key = p384_key(&leaf)?;
    let signature = Signature::from_slice(signature).map_err(|_| unverified())?;
    let signed = encode_cose_sig_structure(protected, payload);
    key.verify(&signed, &signature).map_err(|_| unverified())
}

fn verify_certificate_chain(
    leaf: &[u8],
    cabundle: &[Vec<u8>],
    now_ms: u64,
) -> Result<(), TvcError> {
    let root_der = pinned_root_der()?;
    if hex::encode(Sha256::digest(&root_der)) != AWS_ROOT_SHA256 {
        return Err(unverified());
    }
    let root = Certificate::from_der(&root_der).map_err(|_| unverified())?;
    verify_cert(&root, &root)?;
    assert_root_current(&root, now_ms)?;
    // The bundle's first certificate is an untrusted copy of the root.
    let mut issuers = Vec::with_capacity(cabundle.len());
    for der in cabundle.iter().skip(1) {
        issuers.push((
            Certificate::from_der(der).map_err(|_| unverified())?,
            der.clone(),
        ));
    }
    issuers.push((root, root_der.clone()));
    let mut current = Certificate::from_der(leaf).map_err(|_| unverified())?;
    let mut hops = 1usize;
    let expected = cabundle.len() + 1;
    while hops < expected {
        let issuer_index = issuers
            .iter()
            .position(|(issuer, _)| verify_cert(&current, issuer).is_ok())
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

fn assert_root_current(root: &Certificate, now_ms: u64) -> Result<(), TvcError> {
    let now = UNIX_EPOCH
        .checked_add(Duration::from_millis(now_ms))
        .ok_or_else(unverified)?;
    let validity = &root.tbs_certificate.validity;
    if now < validity.not_before.to_system_time() || now > validity.not_after.to_system_time() {
        return Err(unverified());
    }
    Ok(())
}

fn verify_cert(subject: &Certificate, issuer: &Certificate) -> Result<(), TvcError> {
    let key = p384_key(issuer)?;
    let signature = Signature::from_der(subject.signature.as_bytes().ok_or_else(unverified)?)
        .map_err(|_| unverified())?;
    let tbs = subject.tbs_certificate.to_der().map_err(|_| unverified())?;
    key.verify(&tbs, &signature).map_err(|_| unverified())
}

fn p384_key(cert: &Certificate) -> Result<VerifyingKey, TvcError> {
    let raw = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
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

    #[test]
    fn pinned_aws_root_matches_the_fingerprint_and_signs_itself() {
        let der = pinned_root_der().unwrap();
        assert_eq!(hex::encode(Sha256::digest(&der)), AWS_ROOT_SHA256);
        let root = Certificate::from_der(&der).unwrap();
        verify_cert(&root, &root).unwrap();
        assert_root_current(&root, 1_700_000_000_000).unwrap();
        assert!(assert_root_current(&root, 1_000_000_000_000).is_err());
        assert!(assert_root_current(&root, 2_524_608_000_000).is_err());
    }

    #[test]
    fn wrong_pcr_fails_before_the_certificate_chain() {
        let manifest = [0x11; 32];
        let ephemeral = [0x04; EPHEMERAL_PUBLIC_KEY_LEN];
        let proof = synthetic_boot(&manifest, &ephemeral, &[0; PCR_LEN]);
        let error = verify_boot_proof(
            &ephemeral,
            &proof,
            &[encode_lower_hex(&manifest)],
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
        assert_eq!(error.to_string(), "BootProofUnverified");
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
            &[encode_lower_hex(&manifest)],
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
                cbor_bytes(&[]),
                cbor_container(5, 0, Vec::new()),
                cbor_bytes(&payload),
                cbor_bytes(&[0]),
            ]
            .concat(),
        );
        BootProof {
            attestation: [vec![0xd2], cose].concat(),
            ephemeral_public_key: *ephemeral,
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
        vec![prefix | 24, argument as u8]
    }
}
