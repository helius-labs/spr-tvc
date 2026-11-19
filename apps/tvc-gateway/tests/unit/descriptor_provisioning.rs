use super::*;
use spr_tvc_protocol::OperationKind;

pub const TEST_SECRET: [u8; 32] = [7; 32];
pub const TEST_DESCRIPTOR_TTL_MS: u64 = 86_400_000;

pub fn provisioner() -> Provisioner {
    let secret = Zeroizing::new(TEST_SECRET);
    let public_key = crate::config::public_key_of(&secret).unwrap_or([0; 65]);
    Provisioner {
        secret,
        public_key,
        policy: test_policy(),
        descriptor_ttl_ms: TEST_DESCRIPTOR_TTL_MS,
    }
}

pub fn test_policy() -> ReleasePolicy {
    ReleasePolicy {
        version: API_VERSION,
        release_id: "test".to_owned(),
        network: Network::Devnet,
        tvc_application_id: "test".to_owned(),
        security_domain_id: [9; 32],
        accepted_manifest_digests: Vec::new(),
        accepted_executable_digests: Vec::new(),
        quorum_key_id: "test".to_owned(),
        quorum_key_epoch: 1,
        quorum_public_key: Vec::new(),
        allowed_operations: vec![
            OperationKind::Bootstrap,
            OperationKind::Decrypt,
            OperationKind::Derive,
            OperationKind::TransactionKeys,
            OperationKind::Prove,
        ],
        max_encrypted_request_bytes: 262_144,
        max_encrypted_response_bytes: 262_144,
        turnkey_trust_root_id: "aws-nitro-root-g1".to_owned(),
        turnkey_proof_schema_versions: Vec::new(),
        valid_from_ms: 0,
        expires_at_ms: u64::MAX,
        revocation_epoch: 0,
    }
}

#[test]
fn signed_descriptor_verifies_and_tampering_fails() {
    let provisioner = provisioner();
    let input = crate::enrollment::tests::input();
    let mut descriptor = provisioner.sign(&input).expect("signing failed");
    assert_eq!(provisioner.verify(&descriptor, input.issued_at_ms), Ok(()));
    assert_eq!(
        descriptor.allowed_clients[0].allowed_operations,
        test_policy().allowed_operations
    );
    descriptor.turnkey_wallet_id.push('x');
    assert_eq!(
        provisioner.verify(&descriptor, input.issued_at_ms),
        Err(ApiError::InvalidDescriptor)
    );
}

#[test]
fn a_descriptor_expires_its_lifetime_after_the_owner_signed() {
    let provisioner = provisioner();
    let input = crate::enrollment::tests::input();
    let descriptor = provisioner.sign(&input).expect("signing failed");
    let expires = input.issued_at_ms + TEST_DESCRIPTOR_TTL_MS;
    assert_eq!(descriptor.expires_at_ms, expires);
    assert_eq!(provisioner.sign(&input), Ok(descriptor.clone()));
    let skew = spr_tvc_protocol::constants::MAX_CLOCK_SKEW_MS;
    assert_eq!(provisioner.verify(&descriptor, expires + skew), Ok(()));
    assert_eq!(
        provisioner.verify(&descriptor, expires + skew + 1),
        Err(ApiError::DescriptorExpired)
    );
    // The provisioning signature covers the expiry.
    let mut extended = descriptor;
    extended.expires_at_ms += 1;
    assert_eq!(
        provisioner.verify(&extended, input.issued_at_ms),
        Err(ApiError::InvalidDescriptor)
    );
}

#[test]
fn the_provisioning_key_may_carry_a_0x_prefix() {
    let config = |private_key: String| ProvisioningConfig {
        private_key,
        expected_public_key: hex::encode(
            crate::config::public_key_of(&TEST_SECRET).expect("valid key"),
        ),
        release_path: "unused".into(),
        descriptor_ttl_secs: 86_400,
    };
    assert!(signing_key(&config(format!(" 0x{}\n", "07".repeat(32)))).is_ok());
    assert!(signing_key(&config("07".repeat(31))).is_err());
}
