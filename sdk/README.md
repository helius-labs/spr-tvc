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
const keys = await service.keys(owner);
```

`keys` returns SPR `ShieldedKeys` and does not call Decrypt. Sync opens notes
through `keys.decrypt`; that response carries the plaintexts and the nullifier
secret. A spend reads `nullifierSecret()` and gives it to the SPR prover. That
read reaches the service only when no note has been opened. Call `keys.destroy()`
when finished.

Pass `recipient` to the SPR transfer builder. The transfer publishes the
recipient's Solana address as its owner tag.

A relay can forward ciphertexts and return Boot Proofs. The SDK verifies the
release and signing replica itself. Mainnet uses the SDK's [independent trust anchors](trust/mainnet.json)
and system clock, including when a caller supplies a fresh signed policy.

[Direct Turnkey example](../example) · [Security flow](../enclave/SPEC.md)
