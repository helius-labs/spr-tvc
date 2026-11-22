# @heliuslabs/spr-decryption-service

Connect to a hosted deployment with a matching signed release pin. Supply
its [Boot Proof resolver](src/connection/backend.ts) and the SPR proof service.

```ts
import { createDecryptionService } from "@heliuslabs/spr-decryption-service";

const service = createDecryptionService({
  network: "devnet",
  endpoint: new URL(decryptionServiceUrl),
  resolveBootProof,
});

// The sender looks up the destination for an unregistered owner.
const recipient = await service.address(recipientAddress);

// The recipient supplies a Solana Kit MessagePartialSigner for recipientAddress.
const keys = await service.open(owner, spr.proofService);
```

Pass `recipient` to the SPR transfer builder. The transfer publishes the
recipient's Solana address as its owner tag. `open` signs an empty batch to
obtain the nullifier secret and returns SPR `WalletKeys`. Sync with those keys
to sign and decrypt note batches. Call `keys.destroy()` when finished.

A relay can forward ciphertexts and return Boot Proofs. The SDK verifies the
release and signing replica itself. The supplied prover receives the spend
witness. Mainnet uses the SDK's [independent trust anchors](trust/mainnet.json)
and system clock, including when a caller supplies a fresh signed policy.

[Direct Turnkey example](../example) · [Security flow](../enclave/SPEC.md)


## Native Nitro

Import `createNitroDecryptionService` from
`@heliuslabs/spr-decryption-service/nitro`. Pin two policy publication buckets
with independent AWS owners, plus their regions, the network, security domain,
note seed commitment, minimum sequence and custody epoch, and signer quorum.
The SDK reads both policies and uses the current signed revision. In browsers, the SDK stores the
checkpoint in IndexedDB. Other runtimes supply an atomic durable `policyStore`
scoped to the network and domain. Its `accept` method persists the next
checkpoint before succeeding. Apply `advancesNitroPolicy` against the stored
checkpoint inside the transaction. `current` reads the last committed
checkpoint. The SDK checks it before sending an operation, after a wallet
approval returns, and before opening the reply.
A signed activation advances the checkpoint after a replica attests. A signed
revocation advances it immediately and returns `ReleasePolicyRevoked`.

The same `address` and `open` APIs work with the attested client. The SDK
conveys an unavailable session to the caller so the next action can select
another replica. It never resubmits a wallet approval to a different target.
See [release configuration](../enclave/deploy/nitro/README.md).
