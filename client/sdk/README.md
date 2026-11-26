# @heliuslabs/spr-decryption-service

The client talks to the gatekeeper. The first call opens a session and checks the Boot Proof. Later calls send encrypted operations and check the Boot Proof on each reply. The [spec](../../docs/spec.md) is the path and the trust assumptions.

```ts
import { createGatekeeperDecryptionService } from "@heliuslabs/spr-decryption-service";

const service = createGatekeeperDecryptionService({
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

Mainnet ignores a policy that tries to choose its own trust anchors. The pins are in [trust/mainnet.json](trust/mainnet.json). [`createDecryptionService`](src/client/decryption.ts) is the direct enclave transport, for a caller that already has the enclave URL and fetches Boot Proofs itself.

[Examples](../../examples/typescript) · [Turnkey flow](../../examples/turnkey)
