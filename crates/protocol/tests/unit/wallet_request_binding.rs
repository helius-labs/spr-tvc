use super::*;
use crate::types::{ClientGrant, Network, OperationKind};

#[test]
fn the_client_auth_message_is_the_domain_and_the_hex_request_digest() {
    let digest = [0xab; 32];
    let message = client_auth_message(&digest);
    assert_eq!(
        message,
        format!("spr-tvc-client-auth-v1:{}", "ab".repeat(32))
    );
    assert_eq!(client_auth_digest(&digest), sha256(message.as_bytes()));
}

fn descriptor() -> WalletDescriptor {
    WalletDescriptor {
        version: crate::constants::API_VERSION,
        security_domain_id: [0x11; 32],
        network: Network::Devnet,
        turnkey_organization_id: "00000000-0000-4000-8000-000000000001".to_owned(),
        turnkey_wallet_id: "00000000-0000-4000-8000-000000000002".to_owned(),
        address: "4E2agEUkMiuP3ABYbYTYXuU7bYyqPb3uGsLqs7RDd1U5".to_owned(),
        allowed_clients: vec![ClientGrant {
            client_public_key: vec![0x04; 65],
            allowed_operations: vec![OperationKind::Decrypt],
        }],
        expires_at_ms: 1_800_086_400_000,
        provisioning_signature: vec![0; 64],
    }
}

#[test]
fn the_descriptor_digest_covers_its_expiry() {
    let mut later = descriptor();
    later.expires_at_ms += 1;
    assert_ne!(
        descriptor_digest(&later).expect("digest"),
        descriptor_digest(&descriptor()).expect("digest")
    );
}

#[test]
fn a_descriptor_is_current_until_the_clock_skew_past_its_expiry() {
    let descriptor = descriptor();
    let expires = descriptor.expires_at_ms;
    assert_eq!(descriptor.check_current(0), Ok(()));
    assert_eq!(
        descriptor.check_current(expires + crate::constants::MAX_CLOCK_SKEW_MS),
        Ok(())
    );
    assert_eq!(
        descriptor
            .check_current(expires + crate::constants::MAX_CLOCK_SKEW_MS + 1)
            .map_err(|error| error.code),
        Err(crate::error::ErrorCode::DescriptorExpired)
    );
}

#[test]
fn the_wallet_binding_names_the_wallet_and_not_its_clients() {
    let digest = wallet_binding_digest(&descriptor()).expect("digest");

    let mut other_client = descriptor();
    other_client.allowed_clients[0].client_public_key = vec![0x05; 65];
    other_client.allowed_clients[0].allowed_operations = vec![OperationKind::Derive];
    other_client.expires_at_ms += 1;
    other_client.provisioning_signature = vec![1; 64];
    assert_eq!(
        wallet_binding_digest(&other_client).expect("digest"),
        digest
    );

    let others: [fn(&mut WalletDescriptor); 5] = [
        |d| d.network = Network::Mainnet,
        |d| d.security_domain_id = [0x12; 32],
        |d| d.turnkey_organization_id = "00000000-0000-4000-8000-000000000003".to_owned(),
        |d| d.turnkey_wallet_id = "00000000-0000-4000-8000-000000000004".to_owned(),
        |d| d.address = "11111111111111111111111111111111".to_owned(),
    ];
    for change in others {
        let mut other_wallet = descriptor();
        change(&mut other_wallet);
        assert_ne!(
            wallet_binding_digest(&other_wallet).expect("digest"),
            digest
        );
    }
}
