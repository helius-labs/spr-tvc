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

| Invariant | Cases and coverage |
| --- | --- |
| **Address eligibility.** Service keys and decryption require an eligible Ed25519 address. | Public key lookup works without a signature for a valid address. Both operations reject malformed base58, off-curve addresses, and small-order keys. [Owner authorization](apps/decryption-service/tests/unit/owner_authorization.rs) · [Release and routing](apps/decryption-service/tests/unit/release_binding.rs) |
| **Key separation and continuity.** Derivation binds service keys to the address and Quorum key. | Fixed HKDF and public-key vectors. Changing the address or seed changes both keys. Changing the replica preserves keys under the same Quorum key. Replacing the Quorum key changes them. [Key derivation](apps/decryption-service/tests/unit/key_derivation.rs) · [Release binding](apps/decryption-service/tests/unit/release_binding.rs) |
| **Owner authorization.** Only the verified signer selects service keys. | Valid Ed25519 signature succeeds. Wrong network, claimed signer, modified signature, forged signature, and noncanonical signature fail. An empty batch also requires a signature. [Owner authorization](apps/decryption-service/tests/unit/owner_authorization.rs) |
| **Exact request binding.** Signatures authorize the canonical request for this network. | Mutations to the ID, ciphertext, recipient key, sender key, salt, slot, and label fail. Release ID, manifest, executable, Quorum ID and epoch, version, and response key are checked. Rust and TypeScript agree on the digest and off-chain message vectors. Strict decoding rejects malformed requests. [Owner authorization](apps/decryption-service/tests/unit/owner_authorization.rs) · [Release binding](apps/decryption-service/tests/unit/release_binding.rs) · [Rust vectors](crates/protocol/tests/unit/decryption_request_binding.rs) · [TypeScript vectors](packages/tvc-wallet/src/decryption-service/protocol.test.ts) |
| **Reply privacy.** The response is bound to the original request and encrypted to its signed key. | A second private key cannot open the response. Replaying the same encrypted request keeps the reply readable under the original key. Substituting a valid new response public key fails. The test client verifies the App Proof signature, request and result digests, operation, and proof type. [Response privacy](apps/decryption-service/tests/unit/response_privacy.rs) · [App Proof check](apps/decryption-service/tests/unit/decrypt_flow.rs) |
| **Output isolation.** Every item is opened with the verified signer's derived viewing key. | Correct transfer ciphertext opens, with responses in request order. A different declared recipient key rejects the batch. A foreign ciphertext relabeled with the signer's key does not reveal the foreign plaintext. A ring-deposit item uses a separate cipher domain and requires slot zero. [Output handling](apps/decryption-service/tests/unit/output_handling.rs) |
| **Batch bounds and result shape.** The service handles at most 256 items. | A signed batch of 256 returns 256 plaintexts. A signed batch of 257 fails. A signed empty batch returns no plaintext and its nullifier secret derives the public key returned by `PublicKeys`. [Output handling](apps/decryption-service/tests/unit/output_handling.rs) |
| **Attested connection.** The SDK verifies the release, replica, and operation answer. | Shared client tests cover wrong network, failed Boot Proof, wrong root, PCR or manifest mismatch, and mismatched App Proof signing key. The local decryption route tests exercise discovery and operation wrapping with Boot Proofs, grant rejection, and the absence of enrollment. [Connection tests](packages/tvc-wallet/src/client/connect.test.ts) · [Boot Proof tests](packages/tvc-wallet/src/verify/boot-proof.test.ts) · [Root chain](packages/tvc-wallet/src/verify/boot-proof-chain.test.ts) · [Gateway tests](apps/tvc-gateway/e2e/gateway.e2e.test.ts) |
| **SDK claim and sweep.** The wallet gets the right nullifier identity and verifies outputs before use. | The client supplies ordered results and derives nullifiers and transaction keys from the service identity. The gateway test confirms distinct approvals for opening the identity and decrypting a batch. The SDK retains the valid commitment and drops a correctly decrypted output with a mismatched indexed commitment. The localnet example checks amounts and note counts after claim and sweep. [Client tests](packages/tvc-wallet/src/decryption-service/client.test.ts) · [Gateway tests](apps/tvc-gateway/e2e/gateway.e2e.test.ts) · [Localnet example](examples/typescript-client/examples/unregistered_recipient.ts) |

The local suites use test keys and simulated attestation inputs. Production
assurance also depends on operator custody, approved release contents, the
Nitro trust chain, and the wallet retaining its response private key. The
[service spec](apps/decryption-service/SPEC.md#key-custody-and-trust)
describes those assumptions.

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
