//! Session crypto and mainnet trust-anchor tests covering INV-05 (QOS response envelope round-trip)
//! and INV-20 (fail-closed mainnet anchor pinning, threshold >= 2, and bounded policy lifetime).

use p256::ecdsa::SigningKey;
use qos_p256::encrypt::{P256EncryptPair, P256EncryptPublic};
use spr_tvc_wire::constants::{API_VERSION, EXPECTED_TURNKEY_TRUST_ROOT_ID};
use spr_tvc_wire::release::{sign_release_policy, ReleaseAuthorityKey};
use spr_tvc_wire::types::{ManifestSetMember, ManifestSetPolicy, ReleaseAuthoritySignature};

use super::*;

#[test]
fn qos_envelope_round_trips_the_response_key() {
    let pair = P256EncryptPair::generate();
    let other = P256EncryptPair::generate();
    let public = P256EncryptPublic::from_bytes(&pair.public_key().to_bytes()).unwrap();
    let envelope = public.encrypt(b"opened-note").unwrap();
    let opened = pair.decrypt(&envelope).unwrap();
    assert_eq!(&*opened, b"opened-note");
    assert!(other.decrypt(&envelope).is_err());
    assert!(pair.decrypt(&envelope[..envelope.len() - 1]).is_err());
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

    let mut zero_valid_from = signed.clone();
    zero_valid_from.policy.valid_from_ms = 0;
    zero_valid_from.policy.expires_at_ms = 60_000;
    assert_eq!(
        bind_mainnet_release(&zero_valid_from, &authorities, &pcrs, Some(&trust))
            .unwrap_err()
            .code,
        ErrorCode::ReleasePolicyInvalid
    );

    let mut above_safe_int = signed.clone();
    above_safe_int.policy.valid_from_ms = spr_tvc_wire::constants::MAX_SAFE_INTEGER;
    above_safe_int.policy.expires_at_ms = spr_tvc_wire::constants::MAX_SAFE_INTEGER + 1;
    assert_eq!(
        bind_mainnet_release(&above_safe_int, &authorities, &pcrs, Some(&trust))
            .unwrap_err()
            .code,
        ErrorCode::ReleasePolicyInvalid
    );

    let mut wrong_domain = signed.clone();
    wrong_domain.policy.security_domain_id[0] ^= 1;
    assert_eq!(
        bind_mainnet_release(&wrong_domain, &authorities, &pcrs, Some(&trust))
            .unwrap_err()
            .code,
        ErrorCode::ReleasePolicyInvalid
    );

    let mut wrong_quorum = signed.clone();
    wrong_quorum.policy.quorum_public_key[0] ^= 1;
    assert_eq!(
        bind_mainnet_release(&wrong_quorum, &authorities, &pcrs, Some(&trust))
            .unwrap_err()
            .code,
        ErrorCode::ReleasePolicyInvalid
    );

    let mut wrong_authorities = authorities.clone();
    wrong_authorities.authority_set_id = "other-set".into();
    assert_eq!(
        bind_mainnet_release(&signed, &wrong_authorities, &pcrs, Some(&trust))
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
