# Test invariants

`just ci` runs Rust and TypeScript suites, including the SDK-to-enclave
loopback test. Run `just decryption-e2e` to repeat that test on its own.
The loopback test opens one note for its owner, checks that another owner
cannot, and resends the ciphertext. The same script against a deployed
gatekeeper runs when `SPR_E2E_GATEKEEPER_URL`, `HELIUS_API_KEY` or `API_KEY`,
and `SPR_E2E_RELEASE_PIN` are set. The Rust client runs it with
`cargo test -p spr-tvc-client --test gatekeeper -- --ignored`.
Rust tests live under each crate's `tests/`. SDK unit tests sit beside the
implementation.

`just headless-e2e` adds the local Solana validator, indexer, and prover.
Use a sibling `../zolana` checkout, or set `ZOLANA_DIR`. CI builds
`c5297afa13e8bfb6edadf6408304ef3fc2f8c676`, which includes the process
ownership support used for cleanup. The run owns its ledger and service
processes. The loopback enclave binds an ephemeral port and publishes it to
the test. Pass a port offset to run another Solana localnet.

## Decryption service

| Invariant | Coverage |
| --- | --- |
| Only a signer-capable Solana address gets service keys. | Lookup and decrypt reject malformed, off-curve, and small-order addresses. Forged, missing, and noncanonical signatures fail even for empty batches. [Owner authorization](../decryption-service/tests/unit/owner_authorization.rs) |
| The address and Quorum seed determine the service keys. | Fixed derivation vectors, address and seed separation, and agreement across replicas. [Derivation](../decryption-service/tests/unit/key_derivation.rs) · [Release binding](../decryption-service/tests/unit/release_binding.rs) |
| The owner approves the ordered batch for one network and release. | A change to the signer, request ID, item field, item order, item count, network, or response key invalidates approval. The enclave rejects mismatched release pins, unsupported versions, and unknown fields. Rust and TypeScript agree on the digest and signed Solana message. [Owner authorization](../decryption-service/tests/unit/owner_authorization.rs) · [Release binding](../decryption-service/tests/unit/release_binding.rs) · [Rust vectors](../wire/tests/unit/decryption_request_binding.rs) · [SDK vectors](../client/sdk/tests/wire/decryption.test.ts) |
| Only the signed response key opens the reply, including after replay. | A second key cannot open the reply or replace the signed key. Invalid and compressed response keys fail. [Response privacy](../decryption-service/tests/unit/response_privacy.rs) |
| The enclave uses only the verified signer's viewing key. | An output for another address yields unrelated bytes. Wrong ephemeral key encoding, low-order points, malformed salt, and invalid slots fail the entire batch. Ring deposits use their own cipher domain and require slot zero. [Output handling](../decryption-service/tests/unit/output_handling.rs) |
| The body cap applies before work crosses the next boundary. | There is no item cap and no inflight cap. An empty indexer page of 1,000 50-byte notes measures 675,814 bytes. The service accepts 10 MiB, the indexer's body cap, and rejects a larger body. The page reply fits the same ceiling. Concurrent requests can multiply the cap by the connection count. The SDK splits only when the serialized request would exceed it, before signing or sending. It preserves order and rejects incomplete results. [Page size](../wire/tests/page.rs) · [Enclave batches](../decryption-service/tests/unit/output_handling.rs) · [HTTP limits](../decryption-service/tests/unit/http_and_ping.rs) · [Result limit](../decryption-service/tests/unit/app_proof_signature.rs) · [SDK batching](../client/sdk/tests/client/items.test.ts) · [Before signing](../client/sdk/tests/client/decryption.test.ts) |
| The SDK opens only the authenticated reply to its request. | Wrong proof type, version, signature, request ID, request digest, result digest, operation, scheme, or signing replica fails. The SDK rejects oversized ciphertext, the wrong response key, noncanonical plaintext, and unknown proof fields. [Operation replies](../client/sdk/tests/connection/operations.test.ts) |
| Decrypted notes must match their indexed commitments. | The SDK opens empty and nonempty batches with separate approvals. It discards a note with a mismatched commitment. The localnet example checks the amount and note count after claim and sweep. [SDK keys](../client/sdk/tests/client/keys.test.ts) · [Direct E2E](../examples/turnkey/tests/decryption.test.ts) · [Localnet example](../examples/turnkey/index.ts) |

## Release and transport

| Invariant | Coverage |
| --- | --- |
| Only the reviewed deployment can supply a release pin. | The tool checks the authenticated image digest, runtime, measured executable, launch arguments, debug mode, and Quorum key before live attestation. A wrong image digest, altered manifest, or failed proof keeps the pin from being written. [Policy tooling](../xtask/tests/policy.rs) · [Connection](../client/sdk/tests/connection/connect.test.ts) |
| Release policy authorization requires a valid threshold of distinct keys. | Signed policies fail on another network, expiry, revocation, tampering, or missing signatures. Duplicate signer IDs do not count. Malformed thresholds and the same key under two authority IDs are rejected. [Rust conformance](../wire/tests/conformance.rs) · [SDK conformance](../client/sdk/tests/wire/conformance.test.ts) · [SDK release policy](../client/sdk/tests/wire/releases.test.ts) |
| Discovery and replies are bound to the running QOS replica. | Startup requires the QOS v2 JSON envelope, manifest approvals that meet the threshold, and launch arguments that match the manifest. Debug mode and a pivot environment refuse to boot. The SDK checks a current signed ping, the Nitro root and COSE signature, pinned PCR0–3, PCR17, manifest, and replica key. [QOS loader](../decryption-service/tests/unit/qos_startup.rs) · [Ping](../client/sdk/tests/connection/connect.test.ts) · [Boot Proof](../client/sdk/tests/attestation/boot-proof.test.ts) · [Root certificate](../client/sdk/tests/attestation/boot-proof-chain.test.ts) |
| Release checks bound untrusted discovery and terminate stalled verification. | The release bridge uses the SDK's bounded discovery reader. A single signal covers ping, Boot Proof lookup, and attestation verification. Cargo kills and reaps timed-out check subprocesses and caps captured output. [Live verification](../client/sdk/tests/connection/connect.test.ts) · [Release subprocesses](../xtask/tests/tools.rs) |
| Canonical wire bytes agree across Rust, TypeScript, and QOS. | Strict JSON, UTF-16 key ordering, numeric and hex encodings, P-256 low-S signatures, and size checks. The SDK reproduces the shared envelope vector, and Turnkey's `qos_p256` opens it and rejects the wrong key or a truncated frame. The public health route exposes readiness only. [Wire fixtures](../wire/tests/conformance.rs) · [QOS interoperability](../wire/tests/qos_crate_interop.rs) · [SDK conformance](../client/sdk/tests/wire/conformance.test.ts) |
| One SDK deadline covers verification and every decrypt batch. | The caller's timeout or client default applies to the whole call. Shared verification survives one caller timing out. The SDK stops stalled responses and cancelled approvals, wipes the response key, and refuses a request if the release expires during signing. [Client deadline and owner approval](../client/sdk/tests/client/decryption.test.ts) · [Session lifetime](../client/sdk/tests/connection/session.test.ts) · [HTTP limits](../client/sdk/tests/connection/http.test.ts) · [Boot Proof lookup](../client/sdk/tests/connection/connect.test.ts) |
| Turnkey signs the exact SDK bytes for the expected account. | The adapter uses raw Ed25519 for approvals. It refuses another account's signature and changed transaction messages. [Turnkey signer](../examples/turnkey/tests/turnkey.test.ts) |

The tests use fixtures and simulated attestation inputs. The
[service spec](../decryption-service/SPEC.md#key-custody-and-trust) describes the trust
required of Quorum operators and the release authorities.

## Mainnet release controls

| Invariant | Coverage |
| --- | --- |
| An unapproved build cannot supply a production manifest. | The operator tool requires the reviewed source commit, expected GitHub workflow, protected source ref, and immutable image digest. [Provenance checks](../xtask/tests/stage.rs) |
| The staged mainnet release cannot switch a serving app or replace the known Quorum domain. | Candidate selection permits the first deployment or resumption of the same deployment. The operator tool rejects a shared devnet identity, a different Quorum key, and a one-share manifest. [Release staging](../xtask/tests/stage.rs) · [Approved deployment](../xtask/tests/policy.rs) |
| A release bundle cannot choose its own mainnet trust anchors. | The SDK binds the policy to the independently pinned domain, Quorum key, distinct authority threshold, maximum lifetime, and revocation floor. [Mainnet pins](../client/sdk/tests/wire/mainnet-release.test.ts) |
| The example validates RPC genesis before loading signing credentials. | Preflight rejects mainnet configuration before any network call. It rejects mainnet genesis in both modes and accepts only the devnet genesis for hosted mode. Local mode requires loopback. [Example preflight](../examples/turnkey/tests/setup.test.ts) |
