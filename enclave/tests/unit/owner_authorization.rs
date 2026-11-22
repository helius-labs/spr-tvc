use super::*;

#[test]
fn a_decrypt_needs_the_owner_signature_over_this_request_and_network() {
    let service = service();
    let owner = recipient_signer();
    let (viewing, _) = service_keys(&service, &owner);
    let items = vec![transfer_output(viewing, b"ten usdc", 0)];
    let valid = decrypt(&service, &owner, NETWORK, items.clone());
    assert!(call(&service, &valid).is_ok());

    refused(&service, &decrypt(&service, &owner, other(NETWORK), items));

    type Edit = fn(&mut ServiceRequest);
    let edits: [(&str, Edit); 9] = [
        ("signer", |request| {
            let ServiceOperation::Decrypt { signer, .. } = &mut request.operation else {
                unreachable!()
            };
            *signer = base58(&SigningKey::from_bytes(&[9; 32]));
        }),
        ("signature", |request| {
            let ServiceOperation::Decrypt { signature, .. } = &mut request.operation else {
                unreachable!()
            };
            signature[0] ^= 1;
        }),
        ("deadline", |request| {
            let ServiceOperation::Decrypt { expires_at_ms, .. } = &mut request.operation else {
                unreachable!()
            };
            *expires_at_ms += 1;
        }),
        ("ciphertext", |request| {
            request_items(request)[0].ciphertext[0] ^= 1
        }),
        ("ephemeral viewing key", |request| {
            request_items(request)[0].ephemeral_viewing_public_key[1] ^= 1;
        }),
        ("salt", |request| request_items(request)[0].salt[0] ^= 1),
        ("slot", |request| request_items(request)[0].slot_index = 1),
        ("cipher label", |request| {
            request_items(request)[0].label = DecryptLabel::RingDeposit
        }),
        ("request id", |request| request.request_id[0] ^= 1),
    ];
    let digest = service_request_digest(&valid).unwrap();
    for (field, edit) in edits {
        let mut request = valid.clone();
        edit(&mut request);
        assert_eq!(
            service_request_digest(&request).unwrap() == digest,
            field == "signature",
            "{field}"
        );
        assert_eq!(
            encrypted_response(&service, &request).unwrap_err(),
            Failure::Invalid,
            "{field}",
        );
    }
}

#[test]
fn a_signed_request_expires_before_note_work_or_release() {
    use std::cell::Cell;

    let mut service = service();
    let owner = recipient_signer();
    let request = decrypt(&service, &owner, NETWORK, Vec::new());
    assert!(call(&service, &request).is_ok());

    service.now_ms = || Some(APPROVAL_EXPIRES_AT_MS);
    refused(&service, &request);
    service.now_ms = || Some(APPROVAL_EXPIRES_AT_MS + 1);
    refused(&service, &request);
    service.now_ms = || None;
    assert_eq!(
        encrypted_response(&service, &request),
        Err(Failure::Unavailable)
    );
    assert!(call(&service, &public_keys(&service, &owner)).is_ok());

    let mut unsigned = request.clone();
    let ServiceOperation::Decrypt { signature, .. } = &mut unsigned.operation else {
        unreachable!()
    };
    *signature = [0; 64];
    refused(&service, &unsigned);

    thread_local! {
        static FIRST_READ: Cell<bool> = const { Cell::new(true) };
    }
    service.now_ms =
        || FIRST_READ.with(|first| Some(APPROVAL_EXPIRES_AT_MS - u64::from(first.replace(false))));
    refused(&service, &request);
}

#[test]
fn a_signed_deadline_must_be_within_two_minutes_of_enclave_time() {
    let mut service = service();
    let owner = recipient_signer();
    let request = decrypt(&service, &owner, NETWORK, Vec::new());

    service.now_ms = || Some(APPROVAL_EXPIRES_AT_MS - 120_000);
    assert!(call(&service, &request).is_ok());
    service.now_ms = || Some(APPROVAL_EXPIRES_AT_MS - 120_001);
    refused(&service, &request);
}

#[test]
fn a_signature_binds_the_batch_order_and_length() {
    let service = service();
    let owner = recipient_signer();
    let (viewing, _) = service_keys(&service, &owner);
    let request = decrypt(
        &service,
        &owner,
        NETWORK,
        vec![
            transfer_output(viewing, b"first", 0),
            transfer_output(viewing, b"second", 1),
        ],
    );
    let mut reordered = request.clone();
    request_items(&mut reordered).swap(0, 1);
    refused(&service, &reordered);
    let mut shorter = request;
    let ServiceOperation::Decrypt { items, .. } = &mut shorter.operation else {
        unreachable!()
    };
    items.pop();
    refused(&service, &shorter);
}

fn request_items(request: &mut ServiceRequest) -> &mut [DecryptItem] {
    let ServiceOperation::Decrypt { items, .. } = &mut request.operation else {
        unreachable!()
    };
    items
}

#[test]
fn even_an_empty_batch_requires_the_owners_signature() {
    let service = service();
    let owner = recipient_signer();
    let mut request = decrypt(&service, &owner, NETWORK, Vec::new());
    let message = decrypt_message(
        &owner.verifying_key().to_bytes(),
        NETWORK,
        &service_request_digest(&request).unwrap(),
    );
    let stranger = SigningKey::from_bytes(&[9; 32]);
    let forged = stranger.sign(&message).to_bytes();
    let mut noncanonical = owner.sign(&message).to_bytes();
    noncanonical[32..].fill(0xff);
    for invalid in [[0; 64], forged, noncanonical] {
        let ServiceOperation::Decrypt { signature, .. } = &mut request.operation else {
            unreachable!()
        };
        *signature = invalid;
        refused(&service, &request);
    }
}

#[test]
fn only_an_address_a_key_can_sign_for_has_service_keys() {
    let service = service();
    let off_curve = (0u8..=255)
        .map(|byte| [byte; 32])
        .find(|bytes| ed25519_dalek::VerifyingKey::from_bytes(bytes).is_err())
        .expect("an off-curve address");
    // The identity point, of order one.
    let mut small_order = [0u8; 32];
    small_order[0] = 1;
    let mixed_order = (0u8..=255)
        .filter_map(|byte| ed25519_dalek::VerifyingKey::from_bytes(&[byte; 32]).ok())
        .find(|key| !key.is_weak() && !key.to_edwards().is_torsion_free())
        .expect("a non-small-order point with torsion")
        .to_bytes();
    let noncanonical = (0xedu8..=0xff)
        .filter_map(|low| {
            // Encodes y >= 2^255 - 19 instead of its canonical residue.
            let mut bytes = [0xff; 32];
            bytes[0] = low;
            bytes[31] = 0x7f;
            ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()
        })
        .find(|key| !key.is_weak() && key.to_edwards().compress().as_bytes() != key.as_bytes())
        .expect("a noncanonical point accepted by the decoder")
        .to_bytes();
    for address in [
        Pubkey::new_from_array(off_curve).to_string(),
        Pubkey::new_from_array(small_order).to_string(),
        Pubkey::new_from_array(mixed_order).to_string(),
        Pubkey::new_from_array(noncanonical).to_string(),
        "not base58!".to_owned(),
    ] {
        for operation in [
            ServiceOperation::PublicKeys {
                address: address.clone(),
            },
            ServiceOperation::Decrypt {
                signer: address,
                expires_at_ms: APPROVAL_EXPIRES_AT_MS,
                signature: [0; 64],
                items: Vec::new(),
            },
        ] {
            refused(&service, &request(&service, operation));
        }
    }
}
