# @heliuslabs/spr-decryption-service

TypeScript client for the attested decryption service. Each hosted network
requires a signed pin for the approved deployment. Pass a Solana Kit
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

Senders encrypt note contents to `recipient`. The confidential transfer
flow exposes the recipient's Solana owner tag. Recipients sync with the returned
`WalletKeys` and sign each decrypt batch. Your application supplies the
Turnkey signer, Boot Proof resolver, and SPR indexer, prover, and RPC endpoints.
A browser can use a same-origin relay that forwards encrypted requests and
returns Boot Proofs. The client verifies the proofs.

For mainnet, the SDK pins the authority keys, approved Quorum key and
security domain in [its trust configuration](trust/mainnet.json). A caller may
supply a newly signed policy for that domain. The SDK uses its own trust
anchors and system clock to verify it.

See the [direct Turnkey example](../example) for an
end-to-end integration and the [spec](../enclave/SPEC.md)
for what the client verifies and which keys the enclave holds.
