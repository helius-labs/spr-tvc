//! Boot proof, X.509 certificate chain, COSE_Sign1 ES384, PCR, and manifest verification tests.
//! Covers INV-15 (AWS Nitro root & X.509/ES384 chain), INV-16 (attestation shape, PCR0-3 & PCR17),
//! and INV-17 (strict manifest envelope & approved manifest set).

use super::*;
use crate::ClientError;

#[test]
fn pinned_aws_root_matches_the_fingerprint_and_signs_itself() {
    let der = pinned_root_der().unwrap();
    assert_eq!(hex::encode(Sha256::digest(der)), AWS_ROOT_SHA256);
    let root_cert_der = CertificateDer::from(der);
    anchor_from_trusted_cert(&root_cert_der).unwrap();
    let root = Certificate::from_der(der).unwrap();
    assert_cert_valid_at(&root, 1_700_000_000_000).unwrap();
    assert!(assert_cert_valid_at(&root, 1_000_000_000_000).is_err());
    assert!(assert_cert_valid_at(&root, 2_524_608_000_000).is_err());
}

#[test]
fn wrong_pcr_fails_before_the_certificate_chain() {
    let manifest = [0x11; 32];
    let ephemeral = [0x04; QOS_P256_PUBLIC_LEN];
    let proof = synthetic_boot(&manifest, &ephemeral, &[0; SHA384_LEN]);
    let error = verify_boot_proof(
        &ephemeral,
        &proof,
        &manifest,
        &IdentityPcrs {
            pcr0: [0xff; SHA384_LEN],
            pcr1: [0; SHA384_LEN],
            pcr2: [0; SHA384_LEN],
            pcr3: [0; SHA384_LEN],
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
    let ephemeral = [0x04; QOS_P256_PUBLIC_LEN];
    let pcr0 = [0x22; SHA384_LEN];
    let proof = synthetic_boot(&manifest, &ephemeral, &pcr0);
    let error = verify_boot_proof(
        &ephemeral,
        &proof,
        &manifest,
        &IdentityPcrs {
            pcr0,
            pcr1: [0; SHA384_LEN],
            pcr2: [0; SHA384_LEN],
            pcr3: [0; SHA384_LEN],
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
        &[0x04; QOS_P256_PUBLIC_LEN],
        &BootProof {
            attestation: Vec::new(),
            ephemeral_public_key: [0x04; QOS_P256_PUBLIC_LEN],
            manifest_envelope: Vec::new(),
        },
        &[0x11; 32],
        &IdentityPcrs {
            pcr0: [0; SHA384_LEN],
            pcr1: [0; SHA384_LEN],
            pcr2: [0; SHA384_LEN],
            pcr3: [0; SHA384_LEN],
        },
        1_000_000,
    )
    .unwrap_err();
    assert_eq!(error.detail, Some("decode"));
}

#[test]
fn a_non_sha384_digest_is_the_shape_stage() {
    let manifest = [0x11; 32];
    let ephemeral = [0x04; QOS_P256_PUBLIC_LEN];
    let pcr0 = [0x22; SHA384_LEN];
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
            pcr1: [0; SHA384_LEN],
            pcr2: [0; SHA384_LEN],
            pcr3: [0; SHA384_LEN],
        },
        1_000_000,
    )
    .unwrap_err();
    assert_eq!(error.detail, Some("shape"));
}

#[test]
fn a_clock_reading_of_zero_is_the_timestamp_stage() {
    let manifest = [0x11; 32];
    let ephemeral = [0x04; QOS_P256_PUBLIC_LEN];
    let pcr0 = [0x22; SHA384_LEN];
    let error = verify_boot_proof(
        &ephemeral,
        &synthetic_boot(&manifest, &ephemeral, &pcr0),
        &manifest,
        &IdentityPcrs {
            pcr0,
            pcr1: [0; SHA384_LEN],
            pcr2: [0; SHA384_LEN],
            pcr3: [0; SHA384_LEN],
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
        "../../../../decryption-service/tests/fixtures/qos-0.12.1-manifest-envelope.json"
    );
    let versioned = VersionedManifestEnvelope::try_from_slice_compat(bytes).unwrap();
    let VersionedManifestEnvelope::V2(envelope) = &versioned else {
        panic!("fixture envelope is v2");
    };
    let manifest = &envelope.manifest;
    let pcr = |bytes: &[u8]| -> [u8; SHA384_LEN] { bytes.try_into().unwrap() };
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

    parsed["manifest"]["namespace"]["name"] = serde_json::json!(manifest.namespace.name.clone());
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
    use std::str::FromStr;

    use p384::ecdsa::signature::Signer;
    use p384::ecdsa::SigningKey;
    use p384::pkcs8::EncodePublicKey;
    use x509_cert::der::asn1::{BitString, OctetString};
    use x509_cert::der::oid::{AssociatedOid, ObjectIdentifier};
    use x509_cert::der::Encode;
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
    use x509_cert::ext::Extension;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::time::{Time, Validity};
    use x509_cert::TbsCertificate;

    const OID_ECDSA_WITH_SHA384: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

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
            let spki_doc = p384::PublicKey::from(self.subject_key.verifying_key())
                .to_public_key_der()
                .unwrap();
            let spki = SubjectPublicKeyInfoOwned::from_der(spki_doc.as_bytes()).unwrap();
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
                    not_before: Time::try_from(UNIX_EPOCH + Duration::from_secs(not_before_secs))
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
        &root_der,
        att_ms,
        att_ms,
    )
    .unwrap();
    verify_certificate_chain_against_root(
        &leaf_der,
        &[root_der.clone(), inter_der.clone()],
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
    ephemeral: &[u8; QOS_P256_PUBLIC_LEN],
    pcr0: &[u8; SHA384_LEN],
) -> BootProof {
    let live = live_manifest_pcr(manifest, ephemeral);
    let zeros = [0u8; SHA384_LEN];
    let mut pcr_body = Vec::new();
    for index in 0..PCR_COUNT {
        let value = if index == 0 {
            pcr0.as_slice()
        } else if index == PCR17 as usize {
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
