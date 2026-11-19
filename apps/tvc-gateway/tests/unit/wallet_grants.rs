use spr_tvc_protocol::verify_wallet_grant;

use super::*;

pub const GRANT_SECRET_HEX: &str =
    "0606060606060606060606060606060606060606060606060606060606060606";
const NOW: u64 = 1_800_000_000_000;

fn grant_public_key() -> [u8; 65] {
    crate::config::public_key_of(&[6; 32]).expect("test grant key is invalid")
}

pub fn grants(revoked: Vec<String>) -> WalletGrants {
    let config = WalletGrantConfig {
        private_key: GRANT_SECRET_HEX.to_owned(),
        expected_public_key: hex::encode(grant_public_key()),
        ttl_secs: 120,
        revoked_client_key_ids: revoked,
    };
    WalletGrants::new(&config).expect("wallet grant key is invalid")
}

fn descriptor() -> WalletDescriptor {
    let provisioner = crate::provisioner::tests::provisioner();
    provisioner
        .sign(&crate::enrollment::tests::input())
        .expect("signing failed")
}

#[test]
fn an_issued_grant_satisfies_the_enclave_for_its_lifetime() {
    let descriptor = descriptor();
    let grant = grants(Vec::new())
        .issue(&ProjectId::for_tests("project-a"), &descriptor, NOW)
        .expect("issue failed");
    let client_key_id = client_key_id(&descriptor.allowed_clients[0].client_public_key);
    assert_eq!(grant.project_id, "project-a");
    assert_eq!(grant.expires_at_ms, NOW + 120_000);
    assert!(
        verify_wallet_grant(
            &grant,
            &grant_public_key(),
            &descriptor,
            &client_key_id,
            NOW + 1
        )
        .is_ok()
    );
}

#[test]
fn a_revoked_client_key_gets_no_grant() {
    let descriptor = descriptor();
    let key = &descriptor.allowed_clients[0].client_public_key;
    let revoking = grants(vec![client_key_id(key)]);
    let revoked = Some(ApiError::ClientKeyRevoked);
    assert_eq!(
        revoking
            .issue(&ProjectId::for_tests("project-a"), &descriptor, NOW)
            .err(),
        revoked
    );
    assert_eq!(revoking.check_client_key(key).err(), revoked);
}
