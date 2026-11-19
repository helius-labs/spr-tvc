use super::*;

/// An enclave running the release [`request`] is bound to.
fn state() -> AppState {
    let runtime = runtime();
    AppState {
        info: Arc::new(spr_tvc_enclave::testing::release().service_info(
            &crate::APP,
            [0x33; 32],
            [0x44; 32],
            &runtime.quorum,
            &runtime.ephemeral,
        )),
        runtime: Arc::new(runtime),
    }
}

#[test]
fn a_request_bound_to_another_release_or_quorum_key_is_refused() {
    use spr_tvc_protocol::error::ErrorCode;

    let running = state().info;
    let bound = request(derive_nothing(), descriptor([0x07; 32]));
    assert_eq!(check_request_bindings(&bound, &running), Ok(()));
    type Edit = fn(&mut OperationRequest);
    let cases: [(Edit, ErrorCode); 7] = [
        (
            |request| {
                request.wallet_descriptor.network = match spr_tvc_enclave::NETWORK {
                    Network::Devnet => Network::Mainnet,
                    Network::Mainnet => Network::Devnet,
                }
            },
            ErrorCode::NetworkMismatch,
        ),
        (
            |request| request.quorum_key_epoch = 9,
            ErrorCode::QuorumKeyEpochMismatch,
        ),
        (
            |request| request.target_release_id = "other-release".to_owned(),
            ErrorCode::ReleaseBindingMismatch,
        ),
        (
            |request| request.target_manifest_digest = [0xcc; 32],
            ErrorCode::ReleaseBindingMismatch,
        ),
        (
            |request| request.target_executable_digest = [0xdd; 32],
            ErrorCode::ReleaseBindingMismatch,
        ),
        (
            |request| request.quorum_key_id = "other-quorum".to_owned(),
            ErrorCode::ReleaseBindingMismatch,
        ),
        (
            |request| request.wallet_descriptor.turnkey_wallet_id.clear(),
            ErrorCode::InvalidWalletDescriptor,
        ),
    ];
    for (edit, code) in cases {
        let mut request = bound.clone();
        edit(&mut request);
        assert_eq!(
            check_request_bindings(&request, &running).map_err(|error| error.code),
            Err(code)
        );
    }
}

#[test]
fn bootstrap_refuses_a_presented_state_and_the_rest_require_one() {
    let state = state();
    let wallet = test_wallet();
    let with_state = sealed_request(&state.runtime, &wallet, Operation::Bootstrap);
    assert_eq!(failure(validate(&with_state, &state)), Failure::Invalid);
    for operation in [
        derive_nothing(),
        Operation::Decrypt { items: Vec::new() },
        Operation::TransactionKeys { items: Vec::new() },
        Operation::Prove {
            request: serde_json::Value::Null,
            prover: Box::new(prover_case("/prove/merge_1_1").sealing),
        },
    ] {
        let without_state = request(operation, descriptor(wallet.public_key));
        assert_eq!(failure(validate(&without_state, &state)), Failure::Invalid);
    }
}

#[test]
fn organization_ids_must_be_canonical_uuids() {
    assert!(is_canonical_uuid("00000000-0000-4000-8000-000000000001"));
    assert!(!is_canonical_uuid("00000000-0000-4000-8000-00000000000A"));
    assert!(!is_canonical_uuid("00000000000040008000000000000001"));
    assert!(!is_canonical_uuid("child-org"));
}
