# @heliuslabs/spr-decryption-service

The client checks a signed release, then the Boot Proof of the replica, before it sends a note.

```ts
import { createDecryptionService } from "@heliuslabs/spr-decryption-service";

const service = createDecryptionService({
  network: "devnet",
  endpoint: new URL(decryptionServiceUrl),
  resolveBootProof,
});

const recipient = await service.address(recipientAddress);
const keys = await service.keys(owner);
```

`address` is the destination for an owner who has not registered a wallet. `keys` fetches the shielded keys and does not decrypt. `keys.decrypt` opens notes and returns the nullifier secret with the plaintexts. A spend that has not opened notes calls `nullifierSecret()` once and passes that secret to the SPR prover. Call `keys.destroy()` when finished.

Pass `recipient` to the SPR transfer builder. The transfer publishes the recipient's Solana address.

Mainnet ignores a policy that tries to choose its own trust anchors. The pins are in [trust/mainnet.json](trust/mainnet.json). A gateway can attach the Boot Proofs. The client still checks them. [`createGatekeeperDecryptionService`](src/client/decryption.ts) is that path.

[Examples](../../examples/typescript) · [Turnkey flow](../../examples/turnkey) · [Specification](../../decryption-service/SPEC.md)
