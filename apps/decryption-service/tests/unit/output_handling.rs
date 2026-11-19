use super::*;

#[test]
fn the_owner_decrypts_what_a_sender_encrypted_to_the_service_keys() {
    let service = service();
    let owner = SigningKey::from_bytes(&[5; 32]);
    let (viewing, nullifier) = service_keys(&service, &owner);
    let (stranger, _) = service_keys(&service, &SigningKey::from_bytes(&[9; 32]));
    assert_ne!(viewing, stranger);

    // The second output is for another key, as a dummy under the owner's tag is.
    let items = vec![
        sent(viewing, viewing, b"ten usdc", 3),
        sent(stranger, viewing, b"not ours", 4),
    ];
    let request = decrypt(&service, &owner, NETWORK, items);
    let ServiceResult::Decrypt(outputs) = call(&service, &request).unwrap() else {
        panic!("expected a Decrypt result");
    };

    assert_eq!(outputs.plaintexts[0], b"ten usdc");
    assert_eq!(outputs.plaintexts[1].len(), b"not ours".len());
    assert_ne!(outputs.plaintexts[1], b"not ours");
    assert_eq!(
        NullifierKey::from_secret(outputs.nullifier_secret)
            .pubkey()
            .unwrap(),
        nullifier
    );
}

#[test]
fn a_batch_holds_items_under_the_signers_service_viewing_key() {
    let service = service();
    let owner = SigningKey::from_bytes(&[5; 32]);
    let (viewing, _) = service_keys(&service, &owner);
    let (stranger, _) = service_keys(&service, &SigningKey::from_bytes(&[9; 32]));
    let named_for_another = vec![sent(viewing, stranger, b"ten usdc", 0)];
    refused(
        &service,
        &decrypt(&service, &owner, NETWORK, named_for_another),
    );
}

#[test]
fn a_decrypt_of_nothing_returns_the_nullifier_secret() {
    let service = service();
    let owner = SigningKey::from_bytes(&[5; 32]);
    let (_, nullifier) = service_keys(&service, &owner);
    let request = decrypt(&service, &owner, NETWORK, Vec::new());
    let ServiceResult::Decrypt(outputs) = call(&service, &request).unwrap() else {
        panic!("expected a Decrypt result");
    };
    assert!(outputs.plaintexts.is_empty());
    assert_eq!(
        NullifierKey::from_secret(outputs.nullifier_secret)
            .pubkey()
            .unwrap(),
        nullifier
    );
}

#[test]
fn accepts_256_outputs_and_rejects_257() {
    let service = service();
    let owner = SigningKey::from_bytes(&[5; 32]);
    let (viewing, _) = service_keys(&service, &owner);
    let output = sent(viewing, viewing, b"amount", 0);
    let full = decrypt(&service, &owner, NETWORK, vec![output.clone(); 256]);
    let ServiceResult::Decrypt(result) = call(&service, &full).unwrap() else {
        panic!("expected a Decrypt result");
    };
    assert_eq!(result.plaintexts, vec![b"amount".to_vec(); 256]);

    let overflow = decrypt(&service, &owner, NETWORK, vec![output; 257]);
    refused(&service, &overflow);
}

#[test]
fn a_ring_deposit_uses_its_own_cipher_and_requires_slot_zero() {
    let service = service();
    let owner = SigningKey::from_bytes(&[5; 32]);
    let (viewing, _) = service_keys(&service, &owner);
    let transaction = ViewingKey::new();
    let salt = random_salt();
    let plaintext = b"ring deposit";
    let output = DecryptItem {
        ciphertext: transaction
            .encrypt_ring_deposit(&X25519Pubkey::from_bytes(viewing).unwrap(), plaintext, salt)
            .unwrap(),
        viewing_public_key: viewing.to_vec(),
        transaction_viewing_public_key: transaction.pubkey().as_bytes().to_vec(),
        salt: salt.to_vec(),
        slot_index: 0,
        label: DecryptLabel::RingDeposit,
    };
    let transfer = DecryptItem {
        label: DecryptLabel::Transfer,
        ..output.clone()
    };
    let valid = decrypt(&service, &owner, NETWORK, vec![output.clone(), transfer]);
    let ServiceResult::Decrypt(result) = call(&service, &valid).unwrap() else {
        panic!("expected a Decrypt result");
    };
    assert_eq!(result.plaintexts[0], plaintext);
    assert_ne!(result.plaintexts[1], plaintext);

    let wrong_slot = DecryptItem {
        slot_index: 1,
        ..output
    };
    refused(
        &service,
        &decrypt(&service, &owner, NETWORK, vec![wrong_slot]),
    );
}
