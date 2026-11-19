# @heliuslabs/spr-decryption-service

TypeScript client for wire v2 of the attested decryption service. Each hosted
network requires a signed v2 release pin. Pass a Solana Kit
`MessagePartialSigner` for the recipient and the SPR client's proof service.

```ts
import { createDecryptionService } from "@heliuslabs/spr-decryption-service";

const service = createDecryptionService({
  network: "devnet",
  endpoint: new URL(decryptionServiceUrl),
  resolveBootProof,
});

const recipient = await service.address(owner.address);
const keys = await service.open(owner, spr.proofService);
```

Senders encrypt to `recipient`. Recipients sync with the returned
`WalletKeys` and sign each decrypt batch. Your application supplies the
Turnkey signer, Boot Proof resolver, and SPR indexer, prover, and RPC endpoints.
A browser can use a same-origin relay that forwards encrypted requests and
returns Boot Proofs. The client verifies the proofs.

See the [direct Turnkey example](../example) for an
end-to-end integration and the [spec](../enclave/SPEC.md)
for what the client verifies and which keys the enclave holds.
