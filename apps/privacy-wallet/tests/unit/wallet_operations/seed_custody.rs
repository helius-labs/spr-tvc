use super::*;

#[test]
fn roles_come_only_from_the_wallets_own_derivation_signature() {
    let wallet = test_wallet();
    let roles = Roles::from_seed(&wallet.public_key, &wallet.seed).expect("roles");
    let address = roles.address().expect("address");
    assert_eq!(address.signing_pubkey, roles.owner);
    assert_eq!(address.viewing_pubkey, roles.viewing_key.pubkey());

    let other = test_wallet();
    assert_eq!(
        failure(Roles::from_seed(&other.public_key, &wallet.seed)),
        Failure::Invalid
    );
    let mut tampered = wallet.seed;
    tampered[7] ^= 1;
    assert_eq!(
        failure(Roles::from_seed(&wallet.public_key, &tampered)),
        Failure::Invalid
    );
}

#[test]
fn sealed_seed_hides_the_seed_and_is_bound_to_the_wallet_and_epoch() {
    let runtime = runtime();
    let wallet = test_wallet();
    let request = sealed_request(&runtime, &wallet, derive_nothing());
    let sealed = request.sealed_seed.clone().expect("sealed");
    assert!(!sealed.windows(64).any(|window| window == wallet.seed));

    let expected = Roles::from_seed(&wallet.public_key, &wallet.seed)
        .expect("roles")
        .address()
        .expect("address");
    let (roles, digest) = unseal(&request, &runtime).expect("unseal");
    assert_eq!(digest, sealed_seed_digest(&sealed));
    assert_eq!(roles.address().expect("address"), expected);

    // Another descriptor of the same wallet, for another client key, opens it:
    // a client that signs in again with a new key keeps its sealed seed.
    let mut other_client = request.clone();
    other_client.wallet_descriptor.allowed_clients[0].client_public_key = vec![0x05; 65];
    other_client.wallet_descriptor.provisioning_signature = vec![0x01; 64];
    let (roles, _) = unseal(&other_client, &runtime).expect("another client key");
    assert_eq!(roles.address().expect("address"), expected);

    let mut other_epoch = request.clone();
    other_epoch.quorum_key_epoch = 2;
    assert_eq!(failure(unseal(&other_epoch, &runtime)), Failure::Invalid);

    // Another wallet's descriptor does not.
    let other_network = match spr_tvc_enclave::NETWORK {
        Network::Devnet => Network::Mainnet,
        Network::Mainnet => Network::Devnet,
    };
    let other_address = Pubkey::new_from_array(test_wallet().public_key).to_string();
    let wallet_descriptor = &request.wallet_descriptor;
    let other_wallets = [
        WalletDescriptor {
            network: other_network,
            ..wallet_descriptor.clone()
        },
        WalletDescriptor {
            security_domain_id: [0x12; 32],
            ..wallet_descriptor.clone()
        },
        WalletDescriptor {
            turnkey_organization_id: "00000000-0000-0000-0000-00000000000c".to_owned(),
            ..wallet_descriptor.clone()
        },
        WalletDescriptor {
            turnkey_wallet_id: "other".to_owned(),
            ..wallet_descriptor.clone()
        },
        WalletDescriptor {
            address: other_address,
            ..wallet_descriptor.clone()
        },
    ];
    for descriptor in other_wallets {
        let mut other_wallet = request.clone();
        other_wallet.wallet_descriptor = descriptor;
        assert_eq!(failure(unseal(&other_wallet, &runtime)), Failure::Invalid);
    }

    let other_quorum = runtime_with_quorum(P256Pair::generate().expect("quorum"));
    assert_eq!(failure(unseal(&request, &other_quorum)), Failure::Invalid);

    let mut unsealed = request;
    unsealed.sealed_seed = None;
    assert_eq!(failure(unseal(&unsealed, &runtime)), Failure::Invalid);
}

fn runtime_with_quorum(quorum: P256Pair) -> Runtime {
    let quorum = Arc::new(quorum);
    Runtime {
        ephemeral: Arc::new(P256Pair::generate().expect("ephemeral")),
        custody: Arc::new(TurnkeyCustody::new(Arc::clone(&quorum))),
        quorum,
        provisioning_public: NET.provisioning,
        grant_public: NET.grant,
        prover: production_prover_trust(),
    }
}

#[test]
fn the_same_seed_reseals_under_a_new_quorum_key_to_the_same_identity() {
    let wallet = test_wallet();
    let first = runtime();
    let second = runtime();
    let a = sealed_request(&first, &wallet, derive_nothing());
    let b = sealed_request(&second, &wallet, derive_nothing());
    assert_ne!(a.sealed_seed, b.sealed_seed);
    let (roles_a, _) = unseal(&a, &first).expect("first");
    let (roles_b, _) = unseal(&b, &second).expect("second");
    assert_eq!(
        roles_a.address().expect("address"),
        roles_b.address().expect("address")
    );
    assert_eq!(failure(unseal(&a, &second)), Failure::Invalid);
}
