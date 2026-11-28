//! Enclave output decryption, atomic batch rejection, and ring deposit cipher tests (INV-02, INV-06).

use super::*;

#[test]
fn the_owner_decrypts_what_a_sender_encrypted_to_the_service_keys() {
    let service = service();
    let owner = recipient_signer();
    let (viewing, nullifier) = service_keys(&service, &owner);
    let (stranger, _) = service_keys(&service, &SigningKey::from_bytes(&[9; 32]));
    assert_ne!(viewing, stranger);

    let foreign = transfer_output(stranger, b"not ours", 4);
    let items = vec![transfer_output(viewing, b"ten usdc", 3), foreign];
    let request = decrypt(&service, &owner, NETWORK, items);
    let outputs = decrypted(&service, &request);

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
fn a_bad_output_rejects_the_entire_signed_batch() {
    let service = service();
    let owner = recipient_signer();
    let (viewing, _) = service_keys(&service, &owner);
    let valid = transfer_output(viewing, b"ten usdc", 0);
    let invalid = [
        (
            "non-contributory ephemeral key",
            DecryptItem {
                ephemeral_viewing_public_key: [vec![4], vec![0; 32]].concat(),
                ..valid.clone()
            },
        ),
        (
            "sender key length",
            DecryptItem {
                ephemeral_viewing_public_key: vec![0; 32],
                ..valid.clone()
            },
        ),
        (
            "sender key encoding",
            DecryptItem {
                ephemeral_viewing_public_key: vec![0; 33],
                ..valid.clone()
            },
        ),
        (
            "salt length",
            DecryptItem {
                salt: vec![0; 15],
                ..valid.clone()
            },
        ),
        (
            "transfer slot overflow",
            DecryptItem {
                slot_index: u64::from(u32::MAX) + 1,
                ..valid.clone()
            },
        ),
    ];
    for (case, bad) in invalid {
        let request = decrypt(&service, &owner, NETWORK, vec![valid.clone(), bad]);
        assert_eq!(
            encrypted_response(&service, &request).unwrap_err(),
            Failure::Invalid,
            "{case}",
        );
    }
}

#[test]
fn a_signed_empty_batch_returns_the_nullifier_secret() {
    let service = service();
    let owner = recipient_signer();
    let (_, nullifier) = service_keys(&service, &owner);
    let request = decrypt(&service, &owner, NETWORK, Vec::new());
    let outputs = decrypted(&service, &request);
    assert!(outputs.plaintexts.is_empty());
    assert_eq!(
        NullifierKey::from_secret(outputs.nullifier_secret)
            .pubkey()
            .unwrap(),
        nullifier
    );
}

#[test]
fn a_batch_past_the_old_item_cap_still_opens() {
    let service = service();
    let owner = recipient_signer();
    let (viewing, _) = service_keys(&service, &owner);
    let output = transfer_output(viewing, b"amount", 0);
    let batch = decrypt(&service, &owner, NETWORK, vec![output; 300]);
    let result = decrypted(&service, &batch);
    assert_eq!(result.plaintexts, vec![b"amount".to_vec(); 300]);
}

#[test]
fn a_ring_deposit_uses_its_own_cipher_and_requires_slot_zero() {
    let service = service();
    let owner = recipient_signer();
    let (viewing, _) = service_keys(&service, &owner);
    let transaction = ViewingKey::new();
    let salt = random_salt();
    let plaintext = b"ring deposit";
    let output = DecryptItem {
        ciphertext: transaction
            .encrypt_ring_deposit(&X25519Pubkey::from_bytes(viewing).unwrap(), plaintext, salt)
            .unwrap(),
        ephemeral_viewing_public_key: transaction.pubkey().as_bytes().to_vec(),
        salt: salt.to_vec(),
        slot_index: 0,
        label: DecryptLabel::RingDeposit,
        kdf: spr_tvc_wire::KdfMode::HkdfSha256Ctr,
    };
    let transfer = DecryptItem {
        label: DecryptLabel::Transfer,
        ..output.clone()
    };
    let valid = decrypt(&service, &owner, NETWORK, vec![output.clone(), transfer]);
    let result = decrypted(&service, &valid);
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
