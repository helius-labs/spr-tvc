use super::*;

#[test]
fn decrypt_applies_the_transfer_cipher_under_the_named_viewing_key() {
    use spr_keypair::{random_salt, ViewingKey};

    let wallet = test_wallet();
    let roles = Roles::from_seed(&wallet.public_key, &wallet.seed).expect("roles");
    let transaction_key = ViewingKey::new();
    let salt = random_salt();
    let plaintext = b"opaque to the enclave".to_vec();
    let item = |recipient: &ViewingKey, slot: u32| DecryptItem {
        ciphertext: transaction_key
            .encrypt_slot(&recipient.pubkey(), &plaintext, salt, slot)
            .expect("ciphertext"),
        viewing_public_key: roles.viewing_key.pubkey().as_bytes().to_vec(),
        transaction_viewing_public_key: transaction_key.pubkey().as_bytes().to_vec(),
        salt: salt.to_vec(),
        slot_index: u64::from(slot),
        label: DecryptLabel::Transfer,
    };
    let ring_deposit = DecryptItem {
        ciphertext: transaction_key
            .encrypt_ring_deposit(&roles.viewing_key.pubkey(), &plaintext, salt)
            .expect("ciphertext"),
        slot_index: 0,
        label: DecryptLabel::RingDeposit,
        ..item(&roles.viewing_key, 0)
    };

    let OperationResult::Decrypt { plaintexts } = keys::decrypt(
        &roles,
        &[
            item(&roles.viewing_key, 1),
            item(&ViewingKey::new(), 2),
            ring_deposit,
        ],
    )
    .expect("decrypt") else {
        panic!("expected plaintexts");
    };
    // The cipher is unauthenticated: another wallet's slot answers with bytes
    // that are not the plaintext, never with an error.
    assert_eq!(plaintexts.len(), 3);
    assert_eq!(plaintexts[0], plaintext);
    assert_ne!(plaintexts[1], plaintext);
    assert_eq!(plaintexts[2], plaintext);

    assert_eq!(failure(keys::decrypt(&roles, &[])), Failure::Invalid);
    let stranger = DecryptItem {
        viewing_public_key: ViewingKey::new().pubkey().as_bytes().to_vec(),
        ..item(&roles.viewing_key, 1)
    };
    assert_eq!(
        failure(keys::decrypt(&roles, &[stranger])),
        Failure::Invalid
    );
    let mut truncated = item(&roles.viewing_key, 1);
    truncated.transaction_viewing_public_key.pop();
    assert_eq!(
        failure(keys::decrypt(&roles, &[truncated])),
        Failure::Invalid
    );
    // Only the X25519 tag names a transaction key.
    let mut untagged = item(&roles.viewing_key, 1);
    untagged.transaction_viewing_public_key[0] = 0x02;
    assert_eq!(
        failure(keys::decrypt(&roles, &[untagged])),
        Failure::Invalid
    );
    let ring_slot = DecryptItem {
        slot_index: 1,
        label: DecryptLabel::RingDeposit,
        ..item(&roles.viewing_key, 1)
    };
    assert_eq!(
        failure(keys::decrypt(&roles, &[ring_slot])),
        Failure::Invalid
    );
}

#[test]
fn derive_answers_the_nullifier_and_merge_derivations() {
    use spr_transaction::instructions::merge::{
        merge_dummy_nullifier, merge_output_blinding, merge_output_key, merge_private_tx_blinding,
    };

    let wallet = test_wallet();
    let roles = Roles::from_seed(&wallet.public_key, &wallet.seed).expect("roles");
    let utxo_hash = [3u8; 32];
    let blinding = [4u8; 32];
    let first_nullifier = [5u8; 32];
    let OperationResult::Derive { values } = keys::derive(
        &roles,
        &[
            DeriveItem::Nullifier {
                utxo_hash,
                blinding,
            },
            DeriveItem::MergeDummyNullifier {
                first_nullifier,
                slot_index: 3,
            },
            DeriveItem::MergeOutputBlinding { first_nullifier },
            DeriveItem::MergePrivateTxBlinding { first_nullifier },
            DeriveItem::MergeOutputKey { first_nullifier },
        ],
    )
    .expect("derive") else {
        panic!("expected values");
    };
    assert_eq!(
        values,
        vec![
            roles
                .nullifier_key
                .nullifier(&utxo_hash, &blinding)
                .expect("nullifier"),
            merge_dummy_nullifier(&roles.nullifier_key, &first_nullifier, 3).expect("dummy"),
            merge_output_blinding(&roles.nullifier_key, &first_nullifier).expect("blinding"),
            merge_private_tx_blinding(&roles.nullifier_key, &first_nullifier)
                .expect("private transaction blinding"),
            merge_output_key(&roles.nullifier_key, &first_nullifier).expect("output key"),
        ]
    );
    assert_eq!(
        failure(keys::derive(
            &roles,
            &[DeriveItem::MergeDummyNullifier {
                first_nullifier,
                slot_index: 256,
            }]
        )),
        Failure::Invalid
    );
    assert_eq!(failure(keys::derive(&roles, &[])), Failure::Invalid);
}

#[test]
fn transaction_keys_are_the_per_transaction_viewing_secrets() {
    use spr_keypair::ViewingKey;

    let wallet = test_wallet();
    let roles = Roles::from_seed(&wallet.public_key, &wallet.seed).expect("roles");
    let first_nullifier = [9u8; 32];
    let item = TransactionKeyItem {
        viewing_public_key: roles.viewing_key.pubkey().as_bytes().to_vec(),
        first_nullifier,
    };
    let OperationResult::TransactionKeys { secrets } =
        keys::transaction_keys(&roles, std::slice::from_ref(&item)).expect("keys")
    else {
        panic!("expected secrets");
    };
    let expected = roles
        .viewing_key
        .get_transaction_viewing_key(&first_nullifier)
        .expect("transaction key");
    assert_eq!(secrets, vec![*expected.secret_bytes()]);
    // The secret is a key in its own right and not the viewing secret.
    assert_eq!(
        ViewingKey::from_bytes(&secrets[0]).pubkey(),
        expected.pubkey()
    );
    assert_ne!(secrets[0], *roles.viewing_key.secret_bytes());

    let stranger = TransactionKeyItem {
        viewing_public_key: ViewingKey::new().pubkey().as_bytes().to_vec(),
        ..item
    };
    assert_eq!(
        failure(keys::transaction_keys(&roles, &[stranger])),
        Failure::Invalid
    );
}
