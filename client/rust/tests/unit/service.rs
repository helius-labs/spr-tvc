//! Decryption client tests covering INV-07 (pre-signing batch splitting and request ceiling),
//! INV-09 (owner-signed half-open grant window <= 30m), INV-10 (local validation before key fetch
//! or signature prompt), INV-13 (ordered batch decryption and cached nullifier secret), INV-18
//! (reply App Proof, envelope, and plaintext verification), and INV-29 (expiry recheck after sign).

use std::cell::{Cell, RefCell};

use ed25519_dalek::Signer;
use p256::ecdsa::SigningKey;
use qos_p256::encrypt::P256EncryptPair;
use serde_json::{json, Value};
use spr_tvc_wire::constants::{API_VERSION, TVC_APP_PROOF_SCHEME};
use spr_tvc_wire::crypto::sign_p256_message;
use spr_tvc_wire::decryption_service::{
    parse_service_request, view_grant_digest, view_grant_message, MAX_VIEW_GRANT_MS,
    SERVICE_PROOF_TYPE,
};
use spr_tvc_wire::encoding::{canonicalize_json_value, encode_lower_hex, parse_strict_json};
use spr_tvc_wire::error::ErrorCode;
use spr_tvc_wire::types::{EncryptedRequest, ManifestSetPolicy, Network, ReleasePolicy};

use super::*;

struct Key(ed25519_dalek::SigningKey);

impl Key {
    fn from_seed(seed: u8) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }
}

impl OwnerSigner for Key {
    fn pubkey(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    fn sign_offchain(&self, message: &[u8]) -> Result<[u8; 64], ClientError> {
        Ok(self.0.sign(message).to_bytes())
    }
}

fn policy() -> ReleasePolicy {
    ReleasePolicy {
        version: API_VERSION,
        network: Network::Devnet,
        security_domain_id: [0; 32],
        namespace: "namespace".into(),
        manifest_set: ManifestSetPolicy {
            threshold: 1,
            members: Vec::new(),
        },
        minimum_manifest_nonce: 0,
        quorum_key_id: "quorum".into(),
        quorum_key_epoch: 1,
        quorum_public_key: Vec::new(),
        allowed_operations: Vec::new(),
        max_encrypted_request_bytes: 1,
        max_encrypted_response_bytes: 1,
        turnkey_trust_root_id: "root".into(),
        valid_from_ms: 0,
        expires_at_ms: 1,
        revocation_epoch: 0,
    }
}

fn grant_for(grantee: &Key, not_before_ms: u64, expiry_ms: u64) -> SignViewGrant<'static> {
    SignViewGrant {
        grantee: grantee.pubkey(),
        network: Network::Devnet,
        quorum_key_id: "quorum",
        quorum_key_epoch: 1,
        not_before_ms,
        expiry_ms,
    }
}

fn code(error: ClientError) -> ErrorCode {
    match error {
        ClientError::Protocol(error) => error.code,
        other => panic!("protocol error, got {other}"),
    }
}

#[test]
fn the_owner_signs_the_grant_and_the_grantee_carries_it() {
    let owner = Key::from_seed(1);
    let grantee = Key::from_seed(2);
    let grant = grant_for(&grantee, 1_000, 1_000 + MAX_VIEW_GRANT_MS)
        .sign(&owner)
        .expect("grant");
    let digest = view_grant_digest(&grant).expect("digest");
    owner
        .0
        .verifying_key()
        .verify_strict(
            &view_grant_message(&owner.pubkey(), &digest),
            &ed25519_dalek::Signature::from_bytes(&grant.signature),
        )
        .expect("owner signature");

    let operation =
        decrypt_operation(&grantee, Vec::new(), Some(&grant), &policy(), 1_000).expect("decrypt");
    let ServiceOperation::Decrypt {
        signer,
        grant: carried,
        ..
    } = operation
    else {
        panic!("decrypt operation");
    };
    assert_eq!(signer, bs58::encode(grantee.pubkey()).into_string());
    assert_eq!(
        carried.expect("grant").owner,
        bs58::encode(owner.pubkey()).into_string()
    );

    let other = Key::from_seed(3);
    assert_eq!(
        code(grant_owner(&other, &grant, &policy(), 1_000).expect_err("grantee")),
        ErrorCode::InvalidSignature
    );
    assert_eq!(
        code(
            grant_owner(&grantee, &grant, &policy(), 1_000 + MAX_VIEW_GRANT_MS)
                .expect_err("expired")
        ),
        ErrorCode::ExpiredRequest
    );

    let mut other_network = grant.clone();
    other_network.network = Network::Mainnet;
    assert_eq!(
        code(grant_owner(&grantee, &other_network, &policy(), 1_000).expect_err("network")),
        ErrorCode::InvalidSignature
    );

    // Not yet valid (now < not_before_ms).
    assert_eq!(
        code(grant_owner(&grantee, &grant, &policy(), 999).expect_err("not yet valid")),
        ErrorCode::ExpiredRequest
    );

    // Mismatched quorum_key_id and quorum_key_epoch.
    let mut wrong_quorum_id = grant.clone();
    wrong_quorum_id.quorum_key_id = "other-quorum".into();
    assert_eq!(
        code(grant_owner(&grantee, &wrong_quorum_id, &policy(), 1_000).expect_err("quorum id")),
        ErrorCode::InvalidSignature
    );
    let mut wrong_quorum_epoch = grant.clone();
    wrong_quorum_epoch.quorum_key_epoch = 2;
    assert_eq!(
        code(
            grant_owner(&grantee, &wrong_quorum_epoch, &policy(), 1_000).expect_err("quorum epoch")
        ),
        ErrorCode::InvalidSignature
    );
}

#[test]
fn a_grant_names_someone_else_for_at_most_thirty_minutes() {
    let owner = Key::from_seed(1);
    let grantee = Key::from_seed(2);
    assert_eq!(
        code(
            grant_for(&owner, 1_000, 1_000 + 1)
                .sign(&owner)
                .expect_err("self")
        ),
        ErrorCode::InvalidSignature
    );
    assert_eq!(
        code(
            grant_for(&grantee, 1_000, 1_000)
                .sign(&owner)
                .expect_err("zero span")
        ),
        ErrorCode::ExpiredRequest
    );
    assert_eq!(
        code(
            grant_for(&grantee, 1_000, 999)
                .sign(&owner)
                .expect_err("inverted span")
        ),
        ErrorCode::ExpiredRequest
    );
    assert_eq!(
        code(
            grant_for(&grantee, 1_000, 1_000 + MAX_VIEW_GRANT_MS + 1)
                .sign(&owner)
                .expect_err("span")
        ),
        ErrorCode::ExpiredRequest
    );
}

const P256_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

fn high_s_signature(low_s: &[u8; 64]) -> Vec<u8> {
    let mut high = [0u8; 32];
    let mut borrow = 0u16;
    for i in (0..32).rev() {
        let n = u16::from(P256_N[i]);
        let s = u16::from(low_s[32 + i]);
        high[i] = n.wrapping_sub(s).wrapping_sub(borrow) as u8;
        borrow = u16::from(n < s + borrow);
    }
    let mut out = low_s.to_vec();
    out[32..].copy_from_slice(&high);
    out
}

#[derive(Clone, Copy)]
enum ReplyMutation {
    None,
    ProofType,
    ProofVersion,
    ProofRequestId,
    ProofRequestDigest,
    ProofResultDigest,
    ProofOperation,
    ProofExtraField,
    ProofNonCanonicalPayload,
    ProofWrongScheme,
    ProofBadSignature,
    ProofHighSSignature,
    ResponseWrongVersion,
    ResponseWrongRequestId,
    ResponseOversizedEncryptedResult,
    ResponseTamperedCiphertext,
    EnvelopeWrongReceiver,
    PlaintextNonCanonicalJson,
    PlaintextWrongResultVariant,
}

struct StubChecker {
    policy: ReleasePolicy,
    quorum: P256EncryptPair,
    replica_signing_secret: [u8; 32],
    replica_public: Vec<u8>,
    now_ms: Cell<u64>,
    mutation: ReplyMutation,
    posts: Cell<usize>,
    reply_checks: Cell<usize>,
    batch_sizes: RefCell<Vec<usize>>,
}

impl StubChecker {
    fn new(mutation: ReplyMutation, max_request: u32, max_response: u32) -> Self {
        let quorum = P256EncryptPair::generate();
        let quorum_sign = SigningKey::from_slice(&[7u8; 32])
            .unwrap()
            .verifying_key()
            .to_sec1_point(false);
        let mut quorum_public = Vec::with_capacity(QOS_P256_PUBLIC_LEN);
        quorum_public.extend_from_slice(&quorum.public_key().to_bytes());
        quorum_public.extend_from_slice(quorum_sign.as_bytes());

        let replica_enc = P256EncryptPair::generate();
        let replica_signing_secret = [8u8; 32];
        let replica_sign = SigningKey::from_slice(&replica_signing_secret)
            .unwrap()
            .verifying_key()
            .to_sec1_point(false);
        let mut replica_public = Vec::with_capacity(QOS_P256_PUBLIC_LEN);
        replica_public.extend_from_slice(&replica_enc.public_key().to_bytes());
        replica_public.extend_from_slice(replica_sign.as_bytes());

        let mut policy = policy();
        policy.quorum_public_key = quorum_public;
        policy.allowed_operations = vec![
            OperationKind::ServicePublicKeys,
            OperationKind::ServiceDecrypt,
        ];
        policy.max_encrypted_request_bytes = max_request;
        policy.max_encrypted_response_bytes = max_response;
        policy.valid_from_ms = 0;
        policy.expires_at_ms = 10_000;

        Self {
            policy,
            quorum,
            replica_signing_secret,
            replica_public,
            now_ms: Cell::new(1_000),
            mutation,
            posts: Cell::new(0),
            reply_checks: Cell::new(0),
            batch_sizes: RefCell::new(Vec::new()),
        }
    }

    fn sign_proof(&self, payload_json: &str) -> AppProof {
        let sig = sign_p256_message(&self.replica_signing_secret, payload_json.as_bytes()).unwrap();
        let signature = match self.mutation {
            ReplyMutation::ProofBadSignature => vec![0u8; 64],
            ReplyMutation::ProofHighSSignature => high_s_signature(&sig),
            _ => sig.to_vec(),
        };
        let scheme = match self.mutation {
            ReplyMutation::ProofWrongScheme => "SIGNATURE_SCHEME_TK_API_P256".into(),
            _ => TVC_APP_PROOF_SCHEME.into(),
        };
        let proof_payload = match self.mutation {
            ReplyMutation::ProofNonCanonicalPayload => format!(" {payload_json}"),
            _ => payload_json.to_owned(),
        };
        AppProof {
            scheme,
            public_key: self.replica_public.clone(),
            proof_payload,
            signature,
        }
    }
}

impl CheckReply for StubChecker {
    fn policy(&self) -> &ReleasePolicy {
        &self.policy
    }

    fn now_ms(&self) -> u64 {
        self.now_ms.get()
    }

    fn gate(&self) -> Result<(), TvcError> {
        let now = self.now_ms.get();
        if now < self.policy.valid_from_ms || now > self.policy.expires_at_ms {
            return Err(TvcError::new(ErrorCode::ExpiredRequest));
        }
        Ok(())
    }

    fn post_operation(&self, body: &str, _limit: usize) -> Result<Vec<u8>, ClientError> {
        self.posts.set(self.posts.get() + 1);
        let wire: EncryptedRequest = parse_strict_json(body).unwrap();
        let plain = self.quorum.decrypt(&wire.ciphertext).unwrap();
        let req = parse_service_request(std::str::from_utf8(&plain).unwrap()).unwrap();
        let req_digest = service_request_digest(&req).unwrap();

        let result_struct = match (&req.operation, self.mutation) {
            (ServiceOperation::PublicKeys { .. }, ReplyMutation::PlaintextWrongResultVariant) => {
                ServiceResult::Decrypt(DecryptedOutputs {
                    plaintexts: Vec::new(),
                    nullifier_secret: [9u8; NULLIFIER_SECRET_LEN],
                })
            }
            (ServiceOperation::PublicKeys { .. }, _) => ServiceResult::PublicKeys {
                viewing_public_key: *X25519Pubkey::from_u([3u8; 32]).unwrap().as_bytes(),
                nullifier_public_key: [4u8; 32],
            },
            (ServiceOperation::Decrypt { items, .. }, _) => {
                self.batch_sizes.borrow_mut().push(items.len());
                ServiceResult::Decrypt(DecryptedOutputs {
                    plaintexts: items.iter().map(|i| i.ciphertext.clone()).collect(),
                    nullifier_secret: [9u8; NULLIFIER_SECRET_LEN],
                })
            }
        };

        let mut plaintext = jcs_serialize(&result_struct).unwrap();
        if matches!(self.mutation, ReplyMutation::PlaintextNonCanonicalJson) {
            plaintext = format!(" {plaintext}");
        }

        let receiver_key = match self.mutation {
            ReplyMutation::EnvelopeWrongReceiver => P256EncryptPair::generate().public_key(),
            _ => P256EncryptPublic::from_bytes(&req.client_response_public_key).unwrap(),
        };
        let mut encrypted_result = receiver_key.encrypt(plaintext.as_bytes()).unwrap();
        let signed_result_digest = result_digest(&encrypted_result);

        let mut payload: Value = json!({
            "type": SERVICE_PROOF_TYPE,
            "version": API_VERSION,
            "request_id": encode_lower_hex(&req.request_id),
            "request_digest": encode_lower_hex(&req_digest),
            "result_digest": encode_lower_hex(&signed_result_digest),
            "operation": match req.operation.kind() {
                OperationKind::ServicePublicKeys => "ServicePublicKeys",
                OperationKind::ServiceDecrypt => "ServiceDecrypt",
            },
        });
        match self.mutation {
            ReplyMutation::ProofType => payload["type"] = json!("wrong"),
            ReplyMutation::ProofVersion => payload["version"] = json!(API_VERSION + 1),
            ReplyMutation::ProofRequestId => payload["request_id"] = json!("00".repeat(32)),
            ReplyMutation::ProofRequestDigest => payload["request_digest"] = json!("00".repeat(32)),
            ReplyMutation::ProofResultDigest => payload["result_digest"] = json!("00".repeat(32)),
            ReplyMutation::ProofOperation => payload["operation"] = json!("ServiceDecrypt"),
            ReplyMutation::ProofExtraField => {
                payload["sealed_seed_digest"] = json!("00".repeat(32));
            }
            _ => {}
        }
        let proof_payload = canonicalize_json_value(&payload).unwrap();
        let proof = self.sign_proof(&proof_payload);

        let mut response_version = API_VERSION;
        let mut response_request_id = req.request_id;
        match self.mutation {
            ReplyMutation::ResponseWrongVersion => response_version = API_VERSION + 1,
            ReplyMutation::ResponseWrongRequestId => response_request_id = [0u8; 32],
            ReplyMutation::ResponseOversizedEncryptedResult => {
                encrypted_result = vec![0u8; self.policy.max_encrypted_response_bytes as usize + 1];
            }
            ReplyMutation::ResponseTamperedCiphertext => encrypted_result.push(0),
            _ => {}
        }

        let response = EncryptedResponse {
            version: response_version,
            request_id: response_request_id,
            encrypted_result,
            tvc_app_proof: proof,
        };
        Ok(jcs_serialize(&response).unwrap().into_bytes())
    }

    fn open_http(
        &self,
        body: &[u8],
    ) -> Result<(EncryptedResponse, Option<BootProof>), ClientError> {
        let text = std::str::from_utf8(body).unwrap();
        Ok((parse_strict_json(text)?, None))
    }

    fn check_reply(
        &self,
        proof: &AppProof,
        request_digest: &[u8; SHA256_LEN],
        encrypted_result: &[u8],
        request: &ServiceRequest,
        _: Option<&BootProof>,
    ) -> Result<(), ClientError> {
        self.reply_checks.set(self.reply_checks.get() + 1);
        verify_app_signature(proof)?;
        bind_operation_proof(proof, request_digest, encrypted_result, request)
    }
}

impl OpenNotes for StubChecker {
    fn decrypt_items(
        &self,
        signer: &dyn OwnerSigner,
        items: Vec<DecryptItem>,
        grant: Option<&ViewGrant>,
    ) -> Result<DecryptedOutputs, ClientError> {
        decrypt_items_with(self, signer, items, grant)
    }
}

#[test]
fn exchange_verifies_reply_proof_envelope_and_rejects_field_tampering() {
    let owner = Key::from_seed(11).pubkey();

    // Positive control: untouched reply opens and yields the expected address.
    let ok_checker = StubChecker::new(ReplyMutation::None, 1_000_000, 1_000_000);
    let address = fetch_address(&ok_checker, &owner).expect("valid reply opens");
    assert_eq!(
        address.viewing_pubkey,
        X25519Pubkey::from_u([3u8; 32]).unwrap()
    );
    assert_eq!(address.nullifier_pubkey, [4u8; 32]);
    assert_eq!(ok_checker.reply_checks.get(), 1);

    let protocol_cases = [
        (ReplyMutation::ProofType, ErrorCode::ReleaseBindingMismatch),
        (
            ReplyMutation::ProofVersion,
            ErrorCode::ReleaseBindingMismatch,
        ),
        (
            ReplyMutation::ProofRequestId,
            ErrorCode::ReleaseBindingMismatch,
        ),
        (
            ReplyMutation::ProofRequestDigest,
            ErrorCode::ReleaseBindingMismatch,
        ),
        (
            ReplyMutation::ProofResultDigest,
            ErrorCode::ReleaseBindingMismatch,
        ),
        (
            ReplyMutation::ProofOperation,
            ErrorCode::ReleaseBindingMismatch,
        ),
        (ReplyMutation::ProofExtraField, ErrorCode::UnknownJsonField),
        (
            ReplyMutation::ProofNonCanonicalPayload,
            ErrorCode::TurnkeyEvidenceInvalid,
        ),
        (
            ReplyMutation::ProofWrongScheme,
            ErrorCode::TurnkeyEvidenceInvalid,
        ),
        (
            ReplyMutation::ProofBadSignature,
            ErrorCode::InvalidSignature,
        ),
        (
            ReplyMutation::ProofHighSSignature,
            ErrorCode::HighSSignature,
        ),
        (
            ReplyMutation::ResponseWrongVersion,
            ErrorCode::ReleaseBindingMismatch,
        ),
        (
            ReplyMutation::ResponseTamperedCiphertext,
            ErrorCode::ReleaseBindingMismatch,
        ),
        (
            ReplyMutation::PlaintextNonCanonicalJson,
            ErrorCode::InvalidCanonicalJson,
        ),
        (
            ReplyMutation::PlaintextWrongResultVariant,
            ErrorCode::ReleaseBindingMismatch,
        ),
    ];
    for (mutation, expected) in protocol_cases {
        let checker = StubChecker::new(mutation, 1_000_000, 1_000_000);
        let err = fetch_address(&checker, &owner).expect_err("tampered reply must fail");
        assert_eq!(code(err), expected);
    }

    // Wrong response request_id and oversized encrypted_result are rejected before check_reply.
    let wrong_id = StubChecker::new(ReplyMutation::ResponseWrongRequestId, 1_000_000, 1_000_000);
    assert_eq!(
        code(fetch_address(&wrong_id, &owner).expect_err("wrong request_id")),
        ErrorCode::ReleaseBindingMismatch
    );
    assert_eq!(wrong_id.reply_checks.get(), 0);

    let oversized = StubChecker::new(
        ReplyMutation::ResponseOversizedEncryptedResult,
        1_000_000,
        256,
    );
    assert!(matches!(
        fetch_address(&oversized, &owner),
        Err(ClientError::ResponseTooLarge)
    ));
    assert_eq!(oversized.reply_checks.get(), 0);

    // Ciphertext encrypted to another receiver key fails envelope decryption.
    let wrong_receiver =
        StubChecker::new(ReplyMutation::EnvelopeWrongReceiver, 1_000_000, 1_000_000);
    assert!(matches!(
        fetch_address(&wrong_receiver, &owner),
        Err(ClientError::InvalidEnvelope)
    ));
}

struct CountingSigner<'a> {
    inner: Key,
    signs: Cell<usize>,
    on_sign: Option<Box<dyn Fn() + 'a>>,
}

impl OwnerSigner for CountingSigner<'_> {
    fn pubkey(&self) -> [u8; 32] {
        self.inner.pubkey()
    }

    fn sign_offchain(&self, message: &[u8]) -> Result<[u8; 64], ClientError> {
        self.signs.set(self.signs.get() + 1);
        if let Some(hook) = &self.on_sign {
            hook();
        }
        self.inner.sign_offchain(message)
    }
}

fn note_with_payload(tag: u8, len: usize) -> Note {
    Note {
        ciphertext: vec![tag; len],
        ephemeral_viewing_public_key: [2u8; X25519_PUBLIC_KEY_LEN],
        salt: vec![3u8; 16],
        slot_index: u64::from(tag),
        label: spr_tvc_wire::DecryptLabel::Transfer,
    }
}

#[test]
fn service_keys_splits_batches_before_signing_and_preserves_order() {
    // 2 notes of 500 bytes (~6 KB hex-encrypted) fit under 7_500 bytes; 4 notes (~11 KB) split 2+2.
    let checker = StubChecker::new(ReplyMutation::None, 7_500, 1_000_000);
    let signer = CountingSigner {
        inner: Key::from_seed(12),
        signs: Cell::new(0),
        on_sign: None,
    };
    let mut keys = open_keys(&checker, &signer).unwrap();
    let notes = vec![
        note_with_payload(1, 500),
        note_with_payload(2, 500),
        note_with_payload(3, 500),
        note_with_payload(4, 500),
    ];

    let opened = keys.decrypt(&notes).unwrap();
    assert_eq!(
        opened,
        vec![vec![1; 500], vec![2; 500], vec![3; 500], vec![4; 500]]
    );
    assert_eq!(*checker.batch_sizes.borrow(), vec![2, 2]);
    // Pre-signing ceiling rejected the 4-item batch before prompting the signer.
    assert_eq!(signer.signs.get(), 2);

    // Nullifier secret was cached from the first batch: no extra signature or post.
    let posts_before = checker.posts.get();
    assert_eq!(
        keys.nullifier_secret().unwrap(),
        [9u8; NULLIFIER_SECRET_LEN]
    );
    let seed_a = keys.transaction_viewing_seed().unwrap();
    let seed_b = keys.transaction_viewing_seed().unwrap();
    assert_eq!(seed_a, seed_b);
    assert_eq!(checker.posts.get(), posts_before);
    assert_eq!(signer.signs.get(), 2);

    // A single note exceeding the request ceiling fails before signing or sending.
    let oversized_note = note_with_payload(9, 4_000);
    let err = keys
        .decrypt(&[oversized_note])
        .expect_err("oversized single note must fail");
    assert_eq!(code(err), ErrorCode::RequestTooLarge);
    assert_eq!(signer.signs.get(), 2);
    assert_eq!(checker.posts.get(), posts_before);
}

#[test]
fn exchange_refuses_to_send_when_release_expires_during_signing() {
    let checker = StubChecker::new(ReplyMutation::None, 1_000_000, 1_000_000);
    let expired = Cell::new(false);
    // Advance the checker's clock past expires_at_ms inside sign_offchain.
    let checker_ref = &checker;
    let signer = CountingSigner {
        inner: Key::from_seed(13),
        signs: Cell::new(0),
        on_sign: Some(Box::new(|| {
            expired.set(true);
            checker_ref.now_ms.set(checker_ref.policy.expires_at_ms + 1);
        })),
    };
    let err = decrypt_items_with(&checker, &signer, Vec::new(), None)
        .expect_err("request signed after release expiry must not be sent");
    assert_eq!(code(err), ErrorCode::ExpiredRequest);
    assert!(expired.get());
    assert_eq!(signer.signs.get(), 1);
    assert_eq!(checker.posts.get(), 0);
}
