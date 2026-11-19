# Test invariants

Rust implementation lives in each crate's `src/`. Unit tests live in
`tests/unit/` and retain access to private code through test-only module
declarations. Integration tests and fixtures live under `tests/`. The
gateway is a separate Cargo workspace. TypeScript tests remain with their
packages, and the two end-to-end suites exercise the boundaries between them.

`just test` runs both Rust workspaces with the workspace testkit features
enabled. `just test-ts` runs the TypeScript client tests. `just gateway-e2e`
runs the gateway against both local enclave binaries and a mock Turnkey.
`just headless-e2e` additionally tests the Solana and indexer paths on localnet.

## Decryption service

| Invariant | Tests |
| --- | --- |
| Address eligibility and ownership | Public lookup accepts an eligible Ed25519 address. Both operations reject malformed, off-curve, and small-order addresses. Decrypt rejects the wrong network or signer and missing, forged, or noncanonical signatures, including for empty batches. [Owner authorization](apps/decryption-service/tests/unit/owner_authorization.rs) |
| Keys bind to the address and Quorum key | Fixed derivation vectors cover both keys. Changing the address or Quorum key changes the keys. Replicas sharing the Quorum key produce identical keys. [Derivation](apps/decryption-service/tests/unit/key_derivation.rs) · [Release binding](apps/decryption-service/tests/unit/release_binding.rs) |
| Approval binds the exact request | Changes to the request ID or to any item field invalidate the signature. The enclave checks the version, release ID, manifest, executable, and Quorum ID and epoch. It rejects wallet grants and malformed envelopes. Rust and TypeScript share request-digest and message vectors. [Owner authorization](apps/decryption-service/tests/unit/owner_authorization.rs) · [Release binding](apps/decryption-service/tests/unit/release_binding.rs) · [Rust vectors](crates/protocol/tests/unit/decryption_request_binding.rs) · [TypeScript vectors](packages/tvc-wallet/src/decryption-service/protocol.test.ts) |
| Only the signed response key opens the reply | A second key cannot decrypt replies, including after replay. The original signature fails if the response key changes. Invalid and compressed response keys are rejected. Replies carry an App Proof bound to the request, operation, and encrypted result. [Response privacy](apps/decryption-service/tests/unit/response_privacy.rs) · [Reply assertions](apps/decryption-service/tests/unit/decrypt_flow.rs) |
| Each batch uses only the signer's viewing key | Valid items return in order. A batch with a different declared recipient, malformed sender key or salt, or out-of-range transfer slot fails as a whole. Relabeling a foreign ciphertext yields no foreign plaintext. Ring deposits use a separate cipher domain and slot zero. [Output handling](apps/decryption-service/tests/unit/output_handling.rs) |
| Batch and result bounds | 256 items succeed and 257 fail. A signed empty batch returns a nullifier secret that matches the public lookup. Shared HTTP tests check the request byte ceiling. [Output handling](apps/decryption-service/tests/unit/output_handling.rs) · [HTTP limits](crates/enclave/tests/unit/http_and_ping.rs) |
| Attestation binds the replica to the release | The production loader reports the QOS manifest and executable digests and rejects a mismatched Quorum key. SDK tests reject a wrong network, root, PCR, manifest, or App Proof key. The gateway tests forward Boot Proofs for discovery and operations. [QOS startup](crates/enclave/tests/unit/qos_startup.rs) · [Connection](packages/tvc-wallet/src/client/connect.test.ts) · [Boot Proof](packages/tvc-wallet/src/verify/boot-proof.test.ts) · [Gateway E2E](apps/tvc-gateway/e2e/gateway.e2e.test.ts) |
| Wallet accepts outputs with matching commitments | The SDK derives the service identity and asks for distinct approvals for empty and nonempty batches. The gateway test drops a decrypted output with a mismatched indexed commitment. The localnet example checks amounts and note counts after claim and sweep. [SDK client](packages/tvc-wallet/src/decryption-service/client.test.ts) · [Gateway E2E](apps/tvc-gateway/e2e/gateway.e2e.test.ts) · [Localnet example](examples/typescript-client/examples/unregistered_recipient.ts) |

The tests use fixture keys and simulated attestation inputs. The
[service spec](apps/decryption-service/SPEC.md#key-custody-and-trust)
states the remaining trust assumptions for a live deployment.

## Privacy wallet

| Invariant | Cases and coverage |
| --- | --- |
| **Bootstrap authorizes one wallet.** The seed comes from its owner's derivation signature. | Correct approval completes the original activity. Decline, substitution, cancellation, and deadline fail. Permission propagation gets bounded retries. The request stamp uses the Quorum signing subkey. [Custody](apps/privacy-wallet/tests/unit/bootstrap_custody.rs) · [Turnkey stamp](apps/privacy-wallet/tests/unit/turnkey_request_signing.rs) |
| **Sealed identity is wallet- and Quorum-bound.** | The sealed state hides the seed, rejects another wallet, epoch or Quorum key, and resealing the same seed preserves the identity. [Seed custody](apps/privacy-wallet/tests/unit/wallet_operations/seed_custody.rs) |
| **Key operations respect the wallet's identity and cipher domains.** | Decrypt covers transfer and deposit, malformed keys, wrong identities, and slot limits. Derive covers nullifiers and merge blindings. Transaction keys vary with the first nullifier and reject foreign viewing keys. [Wallet keys](apps/privacy-wallet/tests/unit/wallet_operations/wallet_keys.rs) |
| **Witnesses reach only authorized provers.** | Circuit and shape select the key and route. Only open slots are filled. Policy signers, target, attestation, and recipient key are checked before sealing. The local configuration uses the local attestation format through a gateway prefix. [Prover authorization](apps/privacy-wallet/tests/unit/wallet_operations/prover_authorization.rs) · [Local prover boundary](apps/privacy-wallet/tests/unit/local_prover_boundary.rs) |
| **Operations require the matching release and authorized wallet.** | Network pins and discovery match the image. Bootstrap requires fresh state. Other operations require sealed state. Wrong release, Quorum binding, UUID or grant fails. Expired descriptors expose the typed error. Encrypted endpoint tests cover bootstrap and each operation, another authorized client on the same wallet, and failure stages. [Request binding](apps/privacy-wallet/tests/unit/wallet_operations/request_binding.rs) · [Encrypted operations](apps/privacy-wallet/tests/unit/wallet_operations/encrypted_operations.rs) · [Network pins](apps/privacy-wallet/tests/unit/network_pins.rs) · [Image configuration](apps/privacy-wallet/tests/unit/image_configuration.rs) |

## Shared enclave and protocol

| Invariant | Cases and coverage |
| --- | --- |
| **Discovery binds to the loaded QOS manifest.** | The production loader reads a QOS 0.12.1 v2 manifest envelope and the local key files, reports the manifest and executable digests, and refuses a valid Quorum key that differs from the one in the manifest. [QOS startup](crates/enclave/tests/unit/qos_startup.rs) |
| **Discovery, ping, and errors have a stable HTTP contract.** | Exact health response, runtime keys in discovery, Quorum-only ping decryption, exact signed ping bytes, generic malformed requests, wrong methods, and oversized input rejection. [HTTP and ping](crates/enclave/tests/unit/http_and_ping.rs) |
| **Canonical encoding yields stable signed bytes.** | JCS ordering, hex encoding, decimal `u64`, and typed bodies reject ambiguous forms. Error codes and discovery digests match the committed fixtures. [Canonical JSON](crates/protocol/tests/unit/canonical_json.rs) · [Wire errors](crates/protocol/tests/unit/wire_errors.rs) · [Conformance](crates/protocol/tests/conformance.rs) |
| **Proofs and transport interoperate with QOS.** | ECDSA wire signatures use low-S, and malformed encodings fail. Incorrect keys and truncated envelopes fail. Rust QOS interop and shared vectors pin both implementations. [App Proof signatures](crates/enclave/tests/unit/app_proof_signature.rs) · [Conformance](crates/protocol/tests/conformance.rs) · [QOS interop](crates/protocol/tests/qos_crate_interop.rs) |
| **Identity and authorization are bound and time-limited.** | Client ID format, descriptor expiry and wallet binding, grant scope, signature, window, and signed release threshold and mutation checks. [Client key](crates/protocol/tests/unit/client_key_identity.rs) · [Wallet request binding](crates/protocol/tests/unit/wallet_request_binding.rs) · [Wallet grant binding](crates/protocol/tests/unit/wallet_grant_binding.rs) · [Release conformance](crates/protocol/tests/conformance.rs) |

## Gateway

| Invariant | Cases and coverage |
| --- | --- |
| **Every protected route has a project.** | Gatekeeper credential and project checks, direct Helius API key lookup, malformed and unknown key rejection, entitlement, TTL, and failure caching behavior. Health stays public. [Routing](apps/tvc-gateway/tests/unit/routing_and_authorization.rs) · [Project identity](apps/tvc-gateway/tests/unit/project_identity.rs) · [API key resolution](apps/tvc-gateway/tests/unit/api_key_resolution.rs) |
| **Enrollment and grants remain scoped to the owner, project, and client.** | Enrollment binds the signer, fields, network, domain, and time window. Descriptors reject tampering and expire. Revoked clients receive no new grants. Gateway E2E covers cross-project rejection, descriptor reuse and expiry. [Owner enrollment](apps/tvc-gateway/tests/unit/owner_enrollment.rs) · [Provisioning](apps/tvc-gateway/tests/unit/descriptor_provisioning.rs) · [Grants](apps/tvc-gateway/tests/unit/wallet_grants.rs) · [Gateway E2E](apps/tvc-gateway/e2e/gateway.e2e.test.ts) |
| **Configuration pins the intended network and release.** | Devnet and mainnet overlays, origin credentials, key parsing, valid signed release, and wrong-network, unsigned, expired or empty policy rejection. [Network configuration](apps/tvc-gateway/tests/unit/network_configuration.rs) · [Release policy](apps/tvc-gateway/tests/unit/release_policy.rs) |
| **Concurrency and replay stay scoped.** | Per-project limits, local and shared replay outcomes, cache rotation, Redis failure, retries before forwarding, and Turnkey lookup batching, failure and cancellation. [Limits](apps/tvc-gateway/tests/unit/concurrency_limits.rs) · [Replay](apps/tvc-gateway/tests/unit/replay_isolation.rs) · [Routing](apps/tvc-gateway/tests/unit/routing_and_authorization.rs) · [Turnkey boundary](apps/tvc-gateway/tests/unit/turnkey_boundary.rs) |
| **The gateway contract is stable.** | Generic upstream failures, problem documents, supported routes, oversized responses, and OpenAPI document verification. [Errors](apps/tvc-gateway/tests/unit/public_errors.rs) · [Routing](apps/tvc-gateway/tests/unit/routing_and_authorization.rs) · [OpenAPI](apps/tvc-gateway/tests/unit/openapi_contract.rs) |
