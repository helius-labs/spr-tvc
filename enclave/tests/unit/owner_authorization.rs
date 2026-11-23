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
        ("derivation", |request| {
            let ServiceOperation::Decrypt { derivation, .. } = &mut request.operation else {
                unreachable!()
            };
            *derivation = base58(&SigningKey::from_bytes(&[9; 32]));
        }),
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
    for address in [
        Pubkey::new_from_array(off_curve).to_string(),
        Pubkey::new_from_array(small_order).to_string(),
        "not base58!".to_owned(),
    ] {
        for operation in [
            ServiceOperation::PublicKeys {
                address: address.clone(),
            },
            ServiceOperation::Decrypt {
                derivation: address.clone(),
                signer: address,
                grant: None,
                signature: [0; 64],
                items: Vec::new(),
            },
        ] {
            refused(&service, &request(&service, operation));
        }
    }
}
