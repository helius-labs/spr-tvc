# @heliuslabs/spr-decryption-service

Connect to a hosted deployment with a matching signed release pin. Supply
its [Boot Proof resolver](src/connection/backend.ts).

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
const keys = await service.decrypt(owner);
```

`decrypt` returns SPR `ShieldedKeys`. Sync opens notes through `keys.decrypt`.
A spend takes `keys.nullifierSecret()` to the SPR prover. Call `keys.destroy()`
when finished.

Pass `recipient` to the SPR transfer builder. The transfer publishes the
recipient's Solana address as its owner tag.

A relay can forward ciphertexts and return Boot Proofs. The SDK verifies the
release and signing replica itself. Mainnet uses the SDK's [independent trust anchors](trust/mainnet.json)
and system clock, including when a caller supplies a fresh signed policy.

[Direct Turnkey example](../example) · [Security flow](../enclave/SPEC.md)
