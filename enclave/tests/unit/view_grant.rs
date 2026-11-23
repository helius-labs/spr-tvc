use std::time::{SystemTime, UNIX_EPOCH};

use spr_tvc_protocol::decryption_service::{
    view_grant_digest, view_grant_message, ViewGrant, MAX_VIEW_GRANT_WINDOW_MS,
};

use super::*;

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
    not_before: u64,
    expiry: u64,
) -> ViewGrant {
    let mut grant = ViewGrant {
        derivation: base58(owner),
        grantee: base58(grantee),
        network: service.info.network,
        quorum_key_id: service.info.quorum_key_id.clone(),
        quorum_key_epoch: service.info.quorum_key_epoch,
        not_before,
        expiry,
        signature: [0; 64],
    };
    let digest = view_grant_digest(&grant).unwrap();
    grant.signature = owner
        .sign(&view_grant_message(
            &owner.verifying_key().to_bytes(),
            &digest,
        ))
        .to_bytes();
    grant
}

fn decrypt_as(
    service: &Service,
    derivation: &SigningKey,
    signer: &SigningKey,
    grant: Option<ViewGrant>,
    items: Vec<DecryptItem>,
) -> ServiceRequest {
    let mut request = request(
        service,
        ServiceOperation::Decrypt {
            derivation: base58(derivation),
            signer: base58(signer),
            grant: grant.map(Box::new),
            signature: [0; 64],
            items,
        },
    );
    let message = decrypt_message(
        &signer.verifying_key().to_bytes(),
        service.info.network,
        &service_request_digest(&request).unwrap(),
    );
    let ServiceOperation::Decrypt { signature, .. } = &mut request.operation else {
        unreachable!()
    };
    *signature = signer.sign(&message).to_bytes();
    request
}

#[test]
fn a_grantee_opens_the_derivation_address_during_the_grant_window() {
    let service = service();
    let owner = recipient_signer();
    let grantee = SigningKey::from_bytes(&[9; 32]);
    let (viewing, nullifier) = service_keys(&service, &owner);
    let now = now_ms();
    let request = decrypt_as(
        &service,
        &owner,
        &grantee,
        Some(grant(
            &service,
            &owner,
            &grantee,
            now - 60_000,
            now + 60_000,
        )),
        vec![transfer_output(viewing, b"ten usdc", 0)],
    );
    let outputs = decrypted(&service, &request);
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
    let owner = recipient_signer();
    let grantee = SigningKey::from_bytes(&[9; 32]);
    let now = now_ms();
    let items = Vec::new();
    let valid = grant(&service, &owner, &grantee, now - 60_000, now + 60_000);

    refused(
        &service,
        &decrypt_as(&service, &owner, &grantee, None, items.clone()),
    );
    refused(
        &service,
        &decrypt_as(&service, &owner, &owner, Some(valid.clone()), items.clone()),
    );

    let mut flipped = valid.clone();
    flipped.signature[0] ^= 1;
    refused(
        &service,
        &decrypt_as(&service, &owner, &grantee, Some(flipped), items.clone()),
    );

    let mut other_epoch = valid;
    other_epoch.quorum_key_epoch ^= 1;
    other_epoch.signature = [0; 64];
    let digest = view_grant_digest(&other_epoch).unwrap();
    other_epoch.signature = owner
        .sign(&view_grant_message(
            &owner.verifying_key().to_bytes(),
            &digest,
        ))
        .to_bytes();
    refused(
        &service,
        &decrypt_as(&service, &owner, &grantee, Some(other_epoch), items.clone()),
    );

    for (not_before, expiry) in [
        (now + 60_000, now + 120_000),
        (now - 120_000, now - 60_000),
        (now - 60_000, now - 60_000 + MAX_VIEW_GRANT_WINDOW_MS + 1),
    ] {
        refused(
            &service,
            &decrypt_as(
                &service,
                &owner,
                &grantee,
                Some(grant(&service, &owner, &grantee, not_before, expiry)),
                items.clone(),
            ),
        );
    }
}
