use std::sync::Arc;

use qos_p256::P256Pair;
use spr_keypair::SigningKey;
use spr_prover_tee::{
    Anchors, FixtureProver, NitroFixture, PolicySigners, ReleasePayload, SignedPolicyFile,
    TeePolicy,
};
use spr_tvc_protocol::constants::{API_VERSION, MAX_PROVE_INPUTS};
use spr_tvc_protocol::types::{
    ClientAuthorization, ClientGrant, DecryptItem, DecryptLabel, DeriveItem, Network,
    ProverSealing, TransactionKeyItem, WalletDescriptor,
};

use spr_tvc_protocol::digest::sealed_seed_digest;

use super::sealed::{seal, unseal, Roles};
use super::*;
use crate::custody::TurnkeyCustody;
use crate::network::NET;
use crate::Runtime;

/// The network the image under test serves, as prover policies name it.
const NETWORK: &str = spr_tvc_enclave::NETWORK.as_str();

/// A wallet key plus the seed its derivation message signs to.
struct TestWallet {
    secret: [u8; 32],
    public_key: [u8; 32],
    seed: [u8; 64],
}

fn test_wallet() -> TestWallet {
    let secret = *SigningKey::new_ed25519().secret_bytes();
    let key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let public_key = key.verifying_key().to_bytes();
    let message = spr_keypair::derivation::ed25519_derivation_message(&public_key);
    let seed = ed25519_dalek::Signer::sign(&key, &message).to_bytes();
    TestWallet {
        secret,
        public_key,
        seed,
    }
}

/// The failure of a result whose success value has no `Debug`.
fn failure<T>(result: Result<T, Failure>) -> Failure {
    match result {
        Ok(_) => panic!("expected a failure"),
        Err(failure) => failure,
    }
}

fn runtime() -> Runtime {
    let quorum = Arc::new(P256Pair::generate().expect("quorum"));
    Runtime {
        ephemeral: Arc::new(P256Pair::generate().expect("ephemeral")),
        custody: Arc::new(TurnkeyCustody::new(Arc::clone(&quorum))),
        quorum,
        provisioning_public: NET.provisioning,
        grant_public: NET.grant,
        prover: ProverTrust::image(),
    }
}

const POLICY_SEED: [u8; 32] = [0x99; 32];
const ATTESTED_AT_SECS: u64 = 1_800_000_000;
const ATTESTED_AT_MS: u64 = ATTESTED_AT_SECS * 1_000;

fn policy_signer() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&POLICY_SEED)
}

/// A fixture prover attested for one nonce, the trust that accepts it, and
/// a sealing that names it under a policy file `POLICY_SEED` signed.
struct ProverCase {
    prover: FixtureProver,
    trust: ProverTrust,
    sealing: ProverSealing,
}

fn prover_case(target: &str) -> ProverCase {
    let prover = FixtureProver::from_ikm(&[0x5a; 32]);
    let nonce = [0x11; 32];
    let fixture =
        NitroFixture::at(nonce, ATTESTED_AT_SECS).with_hpke_public_key(prover.hpke_public_key());
    let policy = signed_policy(
        &policy_signer(),
        NETWORK,
        fixture.policy().clone(),
        ATTESTED_AT_SECS + 60,
    );
    ProverCase {
        trust: ProverTrust {
            signers: PolicySigners::new(
                NETWORK,
                vec![policy_signer().verifying_key().to_bytes()],
                1,
            )
            .expect("signers"),
            anchors: fixture.anchors(),
        },
        sealing: ProverSealing {
            target: target.to_owned(),
            nonce,
            attestation: fixture.attestation_json(),
            policy,
        },
        prover,
    }
}

/// A policy file as a network publishes it, signed by `signer`.
fn signed_policy(
    signer: &ed25519_dalek::SigningKey,
    network: &str,
    policy: TeePolicy,
    expires_at: u64,
) -> serde_json::Value {
    let file = sign_policy(signer, network, policy, expires_at - 3_600, expires_at);
    serde_json::to_value(file).expect("policy file")
}

/// The policy a case's file approves, for a test that re-signs an edit of it.
fn approved_policy(case: &ProverCase) -> TeePolicy {
    let file: SignedPolicyFile =
        serde_json::from_value(case.sealing.policy.clone()).expect("policy file");
    let release: ReleasePayload =
        serde_json::from_slice(&hex::decode(&file.release.payload).expect("hex")).expect("release");
    release.policy
}

fn merge_request() -> serde_json::Value {
    serde_json::json!({
        "circuitType": "merge",
        "inputs": [{ "nullifier": "0x1" }],
        "userNullifierSecret": null,
    })
}

fn seal_case(case: &ProverCase) -> Result<spr_tvc_protocol::types::SealedProverRequest, Failure> {
    prove::seal(
        &merge_request(),
        &[0x0a; 32],
        &case.sealing,
        &case.trust,
        ATTESTED_AT_MS,
    )
}

fn descriptor(address: [u8; 32]) -> WalletDescriptor {
    WalletDescriptor {
        version: API_VERSION,
        security_domain_id: [0x11; 32],
        network: spr_tvc_enclave::NETWORK,
        turnkey_organization_id: "00000000-0000-0000-0000-00000000000b".to_owned(),
        turnkey_wallet_id: "test".to_owned(),
        address: Pubkey::new_from_array(address).to_string(),
        allowed_clients: vec![ClientGrant {
            client_public_key: vec![0x04; 65],
            allowed_operations: OPERATIONS.to_vec(),
        }],
        expires_at_ms: 1_900_000_000_000,
        provisioning_signature: vec![0u8; 64],
    }
}

fn request(operation: Operation, descriptor: WalletDescriptor) -> OperationRequest {
    OperationRequest {
        version: API_VERSION,
        request_id: [0x01; 32],
        issued_at_ms: 1_750_000_000_000,
        expires_at_ms: 1_750_000_060_000,
        target_release_id: "release-test".to_owned(),
        target_manifest_digest: [0x33; 32],
        target_executable_digest: [0x44; 32],
        quorum_key_id: "quorum-test".to_owned(),
        quorum_key_epoch: 1,
        wallet_descriptor: descriptor,
        sealed_seed: None,
        client_response_public_key: vec![0u8; 65],
        operation,
        authorization: ClientAuthorization {
            client_key_id: "spr-client-p256-test".to_owned(),
            signature: vec![0u8; 64],
        },
    }
}

fn sealed_request(
    runtime: &Runtime,
    wallet: &TestWallet,
    operation: Operation,
) -> OperationRequest {
    let mut request = request(operation, descriptor(wallet.public_key));
    let (bytes, _) = seal(&request, runtime, &wallet.seed).expect("seal");
    request.sealed_seed = Some(bytes);
    request
}

/// A stateful operation with nothing in it, for tests about the envelope.
fn derive_nothing() -> Operation {
    Operation::Derive { items: Vec::new() }
}

#[path = "wallet_operations/seed_custody.rs"]
mod seed_custody;

#[path = "wallet_operations/wallet_keys.rs"]
mod wallet_keys;

#[path = "wallet_operations/prover_authorization.rs"]
mod prover_authorization;

#[path = "wallet_operations/request_binding.rs"]
mod request_binding;

#[cfg(feature = "local-dev")]
#[path = "wallet_operations/encrypted_operations.rs"]
mod local;
