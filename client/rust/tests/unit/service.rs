//! Decryption client view-grant tests covering INV-09 (owner-signed half-open grant window <= 30m)
//! and INV-10 (local validation before key fetch or signature prompt).

use ed25519_dalek::Signer;
use spr_tvc_wire::constants::API_VERSION;
use spr_tvc_wire::decryption_service::{view_grant_digest, view_grant_message, MAX_VIEW_GRANT_MS};
use spr_tvc_wire::error::ErrorCode;
use spr_tvc_wire::types::{ManifestSetPolicy, Network, ReleasePolicy};

use super::*;

struct Key(ed25519_dalek::SigningKey);

impl Key {
    fn from_seed(seed: u8) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }
}

impl OwnerSigner for Key {
    fn pubkey(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    fn sign_offchain(&self, message: &[u8]) -> Result<[u8; 64], ClientError> {
        Ok(self.0.sign(message).to_bytes())
    }
}

fn policy() -> ReleasePolicy {
    ReleasePolicy {
        version: API_VERSION,
        network: Network::Devnet,
        security_domain_id: [0; 32],
        namespace: "namespace".into(),
        manifest_set: ManifestSetPolicy {
            threshold: 1,
            members: Vec::new(),
        },
        minimum_manifest_nonce: 0,
        quorum_key_id: "quorum".into(),
        quorum_key_epoch: 1,
        quorum_public_key: Vec::new(),
        allowed_operations: Vec::new(),
        max_encrypted_request_bytes: 1,
        max_encrypted_response_bytes: 1,
        turnkey_trust_root_id: "root".into(),
        valid_from_ms: 0,
        expires_at_ms: 1,
        revocation_epoch: 0,
    }
}

fn grant_for(grantee: &Key, not_before_ms: u64, expiry_ms: u64) -> SignViewGrant<'static> {
    SignViewGrant {
        grantee: grantee.pubkey(),
        network: Network::Devnet,
        quorum_key_id: "quorum",
        quorum_key_epoch: 1,
        not_before_ms,
        expiry_ms,
    }
}

fn code(error: ClientError) -> ErrorCode {
    match error {
        ClientError::Protocol(error) => error.code,
        other => panic!("protocol error, got {other}"),
    }
}

#[test]
fn the_owner_signs_the_grant_and_the_grantee_carries_it() {
    let owner = Key::from_seed(1);
    let grantee = Key::from_seed(2);
    let grant = grant_for(&grantee, 1_000, 1_000 + MAX_VIEW_GRANT_MS)
        .sign(&owner)
        .expect("grant");
    let digest = view_grant_digest(&grant).expect("digest");
    owner
        .0
        .verifying_key()
        .verify_strict(
            &view_grant_message(&owner.pubkey(), &digest),
            &ed25519_dalek::Signature::from_bytes(&grant.signature),
        )
        .expect("owner signature");

    let operation =
        decrypt_operation(&grantee, Vec::new(), Some(&grant), &policy(), 1_000).expect("decrypt");
    let ServiceOperation::Decrypt {
        signer,
        grant: carried,
        ..
    } = operation
    else {
        panic!("decrypt operation");
    };
    assert_eq!(signer, bs58::encode(grantee.pubkey()).into_string());
    assert_eq!(
        carried.expect("grant").owner,
        bs58::encode(owner.pubkey()).into_string()
    );

    let other = Key::from_seed(3);
    assert_eq!(
        code(grant_owner(&other, &grant, &policy(), 1_000).expect_err("grantee")),
        ErrorCode::InvalidSignature
    );
    assert_eq!(
        code(
            grant_owner(&grantee, &grant, &policy(), 1_000 + MAX_VIEW_GRANT_MS)
                .expect_err("expired")
        ),
        ErrorCode::ExpiredRequest
    );

    let mut other_network = grant.clone();
    other_network.network = Network::Mainnet;
    assert_eq!(
        code(grant_owner(&grantee, &other_network, &policy(), 1_000).expect_err("network")),
        ErrorCode::InvalidSignature
    );
}

#[test]
fn a_grant_names_someone_else_for_at_most_thirty_minutes() {
    let owner = Key::from_seed(1);
    assert_eq!(
        code(
            grant_for(&owner, 1_000, 1_000 + 1)
                .sign(&owner)
                .expect_err("self")
        ),
        ErrorCode::InvalidSignature
    );
    assert_eq!(
        code(
            grant_for(&Key::from_seed(2), 1_000, 1_000 + MAX_VIEW_GRANT_MS + 1)
                .sign(&owner)
                .expect_err("span")
        ),
        ErrorCode::ExpiredRequest
    );
}
