# @heliuslabs/spr-decryption-service

Connect to a hosted deployment with a matching signed release pin. Supply
its [Boot Proof resolver](src/connection/backend.ts) and the SPR proof service.

```ts
import { createDecryptionService, resolvePaymentAddress } from "@heliuslabs/spr-decryption-service";

const service = createDecryptionService({
  network: "devnet",
  endpoint: new URL(decryptionServiceUrl),
  resolveBootProof,
});

const recipient = await resolvePaymentAddress({ rpc: spr, owner: recipientAddress, service });

// The recipient supplies a Solana Kit MessagePartialSigner for recipientAddress.
const keys = await service.open(owner, spr.proofService);
```

Pass `recipient` to the SPR transfer builder. The resolver reads the
registry through your trusted RPC. After a successful miss it checks the
RPC's Solana genesis hash and asks the matching service for keys. It checks
the registry again before returning those keys. A registration found on
either read takes precedence. Run this when building a payment. The transfer
publishes the recipient's Solana address as its owner tag. `open` signs an
empty batch to obtain the nullifier secret and returns SPR `WalletKeys`. Sync with those keys
to sign and decrypt note batches for that owner, including notes received
through the service before registration. The SDK stops waiting for approval
and signals cancellation when the verified session expires or the caller
cancels. Call `keys.destroy()` when finished to wipe local keys, cancel
pending decrypt and proof calls, and refuse further use of the private keys.

A relay can forward ciphertexts and return Boot Proofs. The SDK verifies the
release and signing replica itself. The supplied prover receives the spend
witness. Mainnet uses the SDK's [independent trust anchors](trust/mainnet.json)
and system clock, including when a caller supplies a fresh signed policy.
Custom HTTP transports must expose response data through a readable
`Response.body` stream so the SDK can enforce its byte limits.

[Direct Turnkey example](../example) · [Security flow](../enclave/SPEC.md)


## Test a standalone SDK build

CI uploads `spr-decryption-sdk-<build-sha>` for the checked-out commit.
Use `gh run download RUN_ID --pattern 'spr-decryption-sdk-*'`, verify
`SHA256SUMS`, and install the tarball with compatible `@heliuslabs/spr`
and `@solana/kit` packages in the wallet project.

## Native Nitro

Import `createNitroDecryptionService` from
`@heliuslabs/spr-decryption-service/nitro`. Pin two policy publication buckets
with independent AWS owners, plus their regions, the network, security domain,
note seed commitment, minimum sequence and its policy digest, minimum custody
epoch, release quorum and three independent `custodyKeys`. Both activation and
revocation require the release quorum and two custody signatures over the
exact policy, including the ordered buckets, regions and owners. The SDK
requires that pair to match its pins in both heads. Browsers store the
checkpoint in IndexedDB.
Other runtimes supply a durable `policyStore` scoped to network and domain.
Its `current()` method rejects malformed records and returns `undefined` for an empty store.
Its `accept(update)` method applies `advancesNitroPolicy` to both authenticated
heads inside the write transaction and saves `update[0].checkpoint`.
The wallet requires an exact match at the checkpoint sequence and an exact
predecessor link at the next sequence. It checks the saved revision before
sending, after owner approval, and before opening a reply. Policy acceptance
commits before replica attestation.
The SDK rechecks the checkpoint before probing each target and before caching
the winning boot. An unsigned lookup can refresh once if another wallet instance
supersedes that checkpoint during attestation.
The wallet refreshes boot attestation after 60 seconds from the start of the
policy fetch. Both elapsed and wall time bound that window. Signed policy and
certificate expiry can end it earlier. A decrypt reads both published heads
before prompting the owner, after signing and before opening the authenticated
reply. A revoked, superseded or unavailable policy stops the exchange. The
approval deadline also bounds those reads and the replica response.

The client uses the first verified boot from its staggered probes. A
recovery-only client refuses `address()` with `ReleasePolicyRecoveryOnly` and
supports owner-signed `open()`. Use new domain pins for sending and retain
separate recovery pins with `recoveryOnly: true` for old notes.

The same `address` and `open` APIs work with the attested client. Nitro allows
12 seconds for an operation's HTTP response within the caller's overall
deadline. An unsigned key lookup can retry once after fresh policy checks and
attestation when a route fails, a reply is bound to another boot, or another
wallet instance advances the checkpoint.
A rate-limit response goes straight to the caller. Each signed
decrypt uses one boot and one wallet approval. After a replica failure, the
next explicit call can establish a fresh session.
See [release configuration](../enclave/deploy/nitro/README.md).
