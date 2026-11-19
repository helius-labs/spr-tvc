# Test invariants

`just ci` runs the Rust and TypeScript suites. `just decryption-e2e` runs the
SDK against a loopback enclave. `just headless-e2e` adds the Solana validator,
indexer, and prover. Rust tests live under each crate's `tests/` and
TypeScript unit tests sit beside the implementation.

## Decryption service

| Invariant | Coverage |
| --- | --- |
| Only a signer-capable Solana address gets service keys. | Lookup and decrypt reject malformed, off-curve, and small-order addresses. Forged, missing, and noncanonical signatures fail even for empty batches. [Owner authorization](../enclave/tests/unit/owner_authorization.rs) |
| The address and Quorum seed determine the service keys. | Fixed derivation vectors, address and seed separation, and agreement across replicas. [Derivation](../enclave/tests/unit/key_derivation.rs) · [Release binding](../enclave/tests/unit/release_binding.rs) |
| The owner approves the ordered batch for one network and release. | A change to the signer, request ID, item field, item order, item count, network, or response key invalidates approval. The enclave rejects mismatched release pins, unsupported versions, and unknown fields. Rust and TypeScript agree on the digest and signed Solana message. [Owner authorization](../enclave/tests/unit/owner_authorization.rs) · [Release binding](../enclave/tests/unit/release_binding.rs) · [Rust vectors](../protocol/tests/unit/decryption_request_binding.rs) · [SDK vectors](../sdk/src/protocol/decryption.test.ts) |
| Only the signed response key opens the reply, including after replay. | A second key cannot open the reply or replace the signed key. Invalid and compressed response keys fail. [Response privacy](../enclave/tests/unit/response_privacy.rs) |
| The enclave uses only the verified signer's viewing key. | An output for another address yields unrelated bytes. Wrong ephemeral key encoding, low-order points, malformed salt, and invalid slots fail the entire batch. Ring deposits use their own cipher domain and require slot zero. [Output handling](../enclave/tests/unit/output_handling.rs) |
| Batch and byte limits apply before work crosses the next boundary. | The enclave accepts 256 items, rejects 257, and bounds HTTP bodies and encrypted results. The SDK splits at 256 or on the serialized byte limit before signing or sending an oversized request. It preserves order and rejects incomplete results. [Enclave batches](../enclave/tests/unit/output_handling.rs) · [HTTP limits](../enclave/tests/unit/http_and_ping.rs) · [Result limit](../enclave/tests/unit/app_proof_signature.rs) · [SDK batching](../sdk/src/client/items.test.ts) · [Before signing](../sdk/src/client/decryption.test.ts) |
| The SDK opens only the authenticated reply to its request. | Wrong proof type, version, signature, request ID, request digest, result digest, operation, scheme, or signing replica fails. The SDK rejects oversized ciphertext, the wrong response key, noncanonical plaintext, and unknown proof fields. [Operation replies](../sdk/src/connection/operations.test.ts) |
| Decrypted notes must match their indexed commitments. | The SDK opens empty and nonempty batches with separate approvals. It discards a note with a mismatched commitment. The localnet example checks the amount and note count after claim and sweep. [SDK keys](../sdk/src/client/keys.test.ts) · [Direct E2E](../example/tests/decryption.test.ts) · [Localnet example](../example/index.ts) |

## Release and transport

| Invariant | Coverage |
| --- | --- |
| Only the approved deployment can supply a release pin. | The policy tool authenticates the Turnkey deployment query, checks app, organization, QOS version, debug mode, executable digest, and Quorum key, and uses the resulting manifest digest for live attestation. Discovery that supplies different identity fields is rejected before ping or Boot Proof lookup. A failed verification reaches no signing step. [Policy tooling](../scripts/release.test.mjs) · [Connection](../sdk/src/connection/connect.test.ts) |
| Release policy authorization requires a valid threshold of distinct keys. | Signed policies fail on another network, expiry, revocation, tampering, or missing signatures. Duplicate signer IDs do not count. Malformed thresholds and the same key under two authority IDs are rejected. [Rust conformance](../protocol/tests/conformance.rs) · [SDK conformance](../sdk/src/protocol/conformance.test.ts) · [SDK release policy](../sdk/src/protocol/releases.test.ts) |
| Discovery and replies are bound to the running QOS replica. | The loader rejects a Quorum key outside its manifest. The SDK checks a current signed ping, the Nitro root and COSE signature, pinned PCR0–3, PCR17, manifest, and replica key. [QOS loader](../enclave/tests/unit/qos_startup.rs) · [Ping](../sdk/src/connection/connect.test.ts) · [Boot Proof](../sdk/src/attestation/boot-proof.test.ts) · [Root certificate](../sdk/src/attestation/boot-proof-chain.test.ts) |
| Canonical wire bytes agree across Rust, TypeScript, and QOS. | Strict JSON, numeric and hex encodings, P-256 low-S signatures, envelope authentication, and size checks. The public health route exposes readiness only. [Wire fixtures](../protocol/tests/conformance.rs) · [QOS interoperability](../protocol/tests/qos_crate_interop.rs) · [SDK conformance](../sdk/src/protocol/conformance.test.ts) |
| Cancellation and deadlines bound verification and HTTP reads. | Shared verification survives one caller leaving, ignores late results, and refreshes an expired policy. The SDK stops stalled responses and cancelled owner approvals, wipes the response key, and refuses a request if the release expires during signing. [Session lifetime](../sdk/src/connection/session.test.ts) · [HTTP limits](../sdk/src/connection/http.test.ts) · [Boot Proof lookup](../sdk/src/connection/connect.test.ts) · [Owner approval](../sdk/src/client/decryption.test.ts) |
| Turnkey signs the exact SDK bytes for the expected account. | The adapter uses raw Ed25519 for approvals. It refuses another account's signature and changed transaction messages. [Turnkey signer](../example/tests/turnkey.test.ts) |

The tests use fixtures and simulated attestation inputs. The
[service spec](../enclave/SPEC.md#key-custody-and-trust) describes the trust
required of Quorum operators and the release authorities.

## Mainnet release controls

| Invariant | Coverage |
| --- | --- |
| An unapproved build cannot supply a production manifest. | The operator tool requires the reviewed source commit, expected GitHub workflow, protected source ref, and immutable image digest. [Provenance checks](../scripts/mainnet-release.test.mjs) |
| The staged release cannot switch a serving app or replace the known Quorum domain. | Candidate selection permits the first deployment or resumption of the same deployment. The operator tool rejects a shared devnet identity, a different Quorum key, and a one-share manifest. [Release staging](../scripts/mainnet-release.test.mjs) · [Approved deployment](../scripts/release.test.mjs) |
| A release bundle cannot choose its own mainnet trust anchors. | The SDK binds the policy to the independently pinned domain, Quorum key, distinct authority threshold, maximum lifetime, and revocation floor. [Mainnet pins](../sdk/src/protocol/mainnet-release.test.ts) |
| The example does not submit mainnet transactions. | It checks the network configuration before contacting services. Hosted devnet also requires acknowledgement of the public owner tag and validates the RPC genesis. [Example preflight](../example/tests/setup.test.ts) |
