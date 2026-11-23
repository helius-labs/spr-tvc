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
registry through your trusted RPC and checks that RPC's Solana genesis
hash before returning a registered address or asking the service for keys.
After a successful miss and service lookup, it checks the registry and
chain again. The second registry read must reach the slot of the first.
A registration found on either read takes precedence. The resolver returns an
address for building the payment. Use the SPR wallet's guarded payment API to
enforce the selected registry state during execution on a network running the
updated registry program. The transfer
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
