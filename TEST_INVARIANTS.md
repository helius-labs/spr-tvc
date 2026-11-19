# Test invariants

Rust implementation lives in each crate's `src/`. Unit tests live in
`tests/unit/` and retain access to private code through test-only module
declarations. Integration tests live under `tests/`, and TypeScript tests
live beside their implementations.

`just ci` runs workspace tests and checks the wire fixtures.
`just decryption-e2e` exercises the SDK against the local enclave testkit.
`just headless-e2e` also exercises the Solana, indexer, and prover paths.

## Decryption service

| Invariant | Tests |
| --- | --- |
| Address eligibility and ownership | Public lookup accepts an eligible Ed25519 address. Both operations reject malformed, off-curve, and small-order addresses. Decrypt rejects the wrong network or signer and missing, forged, or noncanonical signatures, including for empty batches. [Owner authorization](apps/decryption-service/tests/unit/owner_authorization.rs) |
| Keys bind to the address and Quorum key | Fixed derivation vectors cover both keys. Changing the address or Quorum key changes the keys. Replicas sharing the Quorum key produce identical keys. [Derivation](apps/decryption-service/tests/unit/key_derivation.rs) · [Release binding](apps/decryption-service/tests/unit/release_binding.rs) |
| Approval binds the exact request | Changes to the request ID or to any item field invalidate the signature. The enclave checks the version, release ID, manifest, executable, and Quorum ID and epoch. It rejects unknown fields and malformed envelopes. Rust and TypeScript share request-digest and message vectors. [Owner authorization](apps/decryption-service/tests/unit/owner_authorization.rs) · [Release binding](apps/decryption-service/tests/unit/release_binding.rs) · [Rust vectors](crates/protocol/tests/unit/decryption_request_binding.rs) · [TypeScript vectors](packages/decryption-service/src/decryption-service/protocol.test.ts) · [SDK request](packages/decryption-service/src/decryption-service/client.test.ts) |
| Only the signed response key opens the reply | A second key cannot decrypt replies, including after replay. The original signature fails if the response key changes. Invalid and compressed response keys are rejected. Replies carry an App Proof bound to the request, operation, and encrypted result. [Response privacy](apps/decryption-service/tests/unit/response_privacy.rs) · [Reply assertions](apps/decryption-service/tests/unit/decrypt_flow.rs) |
| Each batch uses only the signer's viewing key | Valid items return in order. A batch with a different declared recipient, malformed sender key or salt, or out-of-range transfer slot fails as a whole. Relabeling a foreign ciphertext yields no foreign plaintext. Ring deposits use a separate cipher domain and slot zero. [Output handling](apps/decryption-service/tests/unit/output_handling.rs) |
| Batch and result bounds | 256 items succeed and 257 fail. A signed empty batch returns a nullifier secret that matches the public lookup. Shared HTTP tests check the request byte ceiling. [Output handling](apps/decryption-service/tests/unit/output_handling.rs) · [HTTP limits](crates/enclave/tests/unit/http_and_ping.rs) |
| Attestation binds the replica to the release | The production loader reports the QOS manifest and executable digests and rejects a mismatched Quorum key. SDK tests reject a wrong network, root, PCR, manifest, or App Proof key. [QOS startup](crates/enclave/tests/unit/qos_startup.rs) · [Connection](packages/decryption-service/src/client/connect.test.ts) · [Boot Proof](packages/decryption-service/src/verify/boot-proof.test.ts) |
| Wallet accepts outputs with matching commitments | The SDK derives the service identity and asks for distinct approvals for empty and nonempty batches. The direct end-to-end test drops a decrypted output with a mismatched indexed commitment. The localnet example checks amounts and note counts after claim and sweep. [Wallet keys](packages/decryption-service/src/decryption-service/keys.test.ts) · [Direct E2E](examples/typescript-client/src/direct.test.ts) · [Localnet example](examples/typescript-client/examples/unregistered_recipient.ts) |
| Turnkey signs the SDK’s exact bytes | The adapter requests raw Ed25519 signing and rejects another account’s signature or a changed transaction message. [Turnkey signer](examples/typescript-client/src/lib.test.ts) |

The tests use fixture keys and simulated attestation inputs. The
[service spec](apps/decryption-service/SPEC.md#key-custody-and-trust)
states the remaining trust assumptions for a live deployment.

## Shared enclave and protocol

| Invariant | Cases and coverage |
| --- | --- |
| **Discovery binds to the loaded QOS manifest.** | The production loader reads a QOS 0.12.1 v2 manifest envelope and the local key files, reports the manifest and executable digests, and refuses a valid Quorum key that differs from the one in the manifest. [QOS startup](crates/enclave/tests/unit/qos_startup.rs) |
| **Discovery, ping, and errors have a stable HTTP contract.** | Exact health response, runtime keys in discovery, Quorum-only ping decryption, exact signed ping bytes, generic malformed requests, wrong methods, and oversized input rejection. [HTTP and ping](crates/enclave/tests/unit/http_and_ping.rs) |
| **Canonical encoding yields stable signed bytes.** | JCS ordering, hex encoding, decimal `u64`, and typed bodies reject ambiguous forms. Error codes and discovery digests match the committed fixtures. [Canonical JSON](crates/protocol/tests/unit/canonical_json.rs) · [Wire errors](crates/protocol/tests/unit/wire_errors.rs) · [Conformance](crates/protocol/tests/conformance.rs) |
| **Proofs and transport interoperate with QOS.** | ECDSA wire signatures use low-S, and malformed encodings fail. Incorrect keys and truncated envelopes fail. Rust QOS interop and shared vectors pin both implementations. [App Proof signatures](crates/enclave/tests/unit/app_proof_signature.rs) · [Conformance](crates/protocol/tests/conformance.rs) · [QOS interop](crates/protocol/tests/qos_crate_interop.rs) |
