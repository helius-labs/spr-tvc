use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::Signer as _;
use spr_keypair::NullifierKey;
use spr_tvc_protocol::decryption_service::{
    decrypt_message, service_request_digest, view_grant_digest, view_grant_message, ViewGrant,
    MAX_VIEW_GRANT_MS,
};
use spr_tvc_protocol::types::DecryptItem;

use super::{
    base58, decrypted, refused, request, service, service_keys, transfer_output, Service,
    ServiceOperation, ServiceRequest, SigningKey,
};

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn grant(
    service: &Service,
    owner: &SigningKey,
    grantee: &SigningKey,
    not_before_ms: u64,
    expiry_ms: u64,
) -> ViewGrant {
    let mut grant = ViewGrant {
        owner: base58(owner),
        grantee: base58(grantee),
        network: service.info.network,
        quorum_key_id: service.info.quorum_key_id.clone(),
        quorum_key_epoch: service.info.quorum_key_epoch,
        not_before_ms,
        expiry_ms,
        signature: [0; 64],
    };
    grant.signature = sign(owner, &grant);
    grant
}

fn sign(owner: &SigningKey, grant: &ViewGrant) -> [u8; 64] {
    owner
        .sign(&view_grant_message(
            &owner.verifying_key().to_bytes(),
            &view_grant_digest(grant).unwrap(),
        ))
        .to_bytes()
}

fn signed(
    service: &Service,
    signer: &SigningKey,
    items: Vec<DecryptItem>,
    grant: Option<ViewGrant>,
) -> ServiceRequest {
    let mut request = request(
        service,
        ServiceOperation::Decrypt {
            signer: base58(signer),
            signature: [0; 64],
            items,
            grant: grant.map(Box::new),
        },
    );
    let message = decrypt_message(
        &signer.verifying_key().to_bytes(),
        service.info.network,
        &service_request_digest(&request).unwrap(),
    );
    let ServiceOperation::Decrypt { signature, .. } = &mut request.operation else {
        unreachable!("request is a Decrypt");
    };
    *signature = signer.sign(&message).to_bytes();
    request
}

#[test]
fn a_grantee_opens_the_owners_notes_during_the_window() {
    let service = service();
    let owner = SigningKey::from_bytes(&[5; 32]);
    let grantee = SigningKey::from_bytes(&[9; 32]);
    let (viewing, nullifier) = service_keys(&service, &owner);
    let now = now_ms();
    let outputs = decrypted(
        &service,
        &signed(
            &service,
            &grantee,
            vec![transfer_output(viewing, b"ten usdc", 0)],
            Some(grant(
                &service,
                &owner,
                &grantee,
                now - 60_000,
                now + 60_000,
            )),
        ),
    );
    assert_eq!(outputs.plaintexts, [b"ten usdc".to_vec()]);
    assert_eq!(
        NullifierKey::from_secret(outputs.nullifier_secret)
            .pubkey()
            .unwrap(),
        nullifier
    );
}

#[test]
fn a_grant_is_refused_outside_its_rules() {
    let service = service();
    let owner = SigningKey::from_bytes(&[5; 32]);
    let grantee = SigningKey::from_bytes(&[9; 32]);
    let (viewing, _) = service_keys(&service, &owner);
    let items = vec![transfer_output(viewing, b"ten usdc", 0)];
    let now = now_ms();
    let valid = grant(&service, &owner, &grantee, now - 60_000, now + 60_000);

    refused(
        &service,
        &signed(
            &service,
            &grantee,
            items.clone(),
            Some(grant(
                &service,
                &owner,
                &grantee,
                now - 120_000,
                now - 60_000,
            )),
        ),
    );

    let mut too_long = valid.clone();
    too_long.not_before_ms = now - 60_000;
    too_long.expiry_ms = too_long.not_before_ms + MAX_VIEW_GRANT_MS + 1;
    too_long.signature = sign(&owner, &too_long);
    refused(
        &service,
        &signed(&service, &grantee, items.clone(), Some(too_long)),
    );

    refused(
        &service,
        &signed(&service, &owner, items.clone(), Some(valid.clone())),
    );

    let mut flipped = valid.clone();
    flipped.signature[0] ^= 0xff;
    refused(
        &service,
        &signed(&service, &grantee, items.clone(), Some(flipped)),
    );

    let mut other_epoch = valid;
    other_epoch.quorum_key_epoch = other_epoch.quorum_key_epoch.wrapping_add(1);
    other_epoch.signature = sign(&owner, &other_epoch);
    refused(
        &service,
        &signed(&service, &grantee, items, Some(other_epoch)),
    );
}
