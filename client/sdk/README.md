# @heliuslabs/spr-decryption-service

The client checks the signed release pin, then posts each operation. The reply carries that replica's Boot Proof. The client checks the Boot Proof and the App Proof before it opens the result. The [spec](../../docs/spec.md) is the path and the trust assumptions.

```ts
import { createDecryptionService } from "@heliuslabs/spr-decryption-service";

const service = createDecryptionService({
  network: "devnet",
  endpoint: new URL("https://devnet.helius-rpc.com"),
  apiKey,
  release,
});

const recipient = await service.address(recipientAddress);
const keys = await service.keys(owner);
```

`address` is the destination for an owner who has not registered a wallet. `keys` fetches the shielded keys and does not decrypt. `keys.decrypt` opens notes and returns the nullifier secret with the plaintexts. A spend that has not opened notes calls `nullifierSecret()` once and passes that secret to the SPR prover. Call `keys.destroy()` when finished.

Pass `recipient` to the SPR transfer builder. The transfer publishes the recipient's Solana address.

Mainnet ignores a policy that tries to choose its own trust anchors. The pins are in [trust/mainnet.json](trust/mainnet.json). Pass `resolveBootProof` instead of `apiKey` to dial an enclave URL and fetch each Boot Proof.

[Examples](../../examples/typescript) · [Turnkey flow](../../examples/turnkey)
