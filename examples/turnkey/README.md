# Confidential transfer with Turnkey

The example uses a Turnkey-managed Solana account to sign transactions and
decrypt approvals. It deposits SOL, sends to the address's service keys,
claims the note, then sweeps it into the account's locally derived shielded
wallet. The on-chain transfer publishes the recipient's Solana owner tag.
The code verifies the recipient and the decryption service before depositing. The [spec](../../docs/spec.md) is that service.

## Devnet

Run this example against a deployed enclave with a matching signed SDK release pin.

1. Create or select a funded Turnkey Solana account with no SPR registry record.
2. Copy [`client.env.example`](client.env.example) to `.env` in this directory.
   Fill in the wallet's Turnkey credentials and the decryption app's
   separate Boot Proof credentials. Set `EXAMPLE_ACCEPT_PUBLIC_RECIPIENT=1`
   to acknowledge that the owner tag will be public.
3. Set `API_KEY` for Helius RPC, indexer, and prover endpoints, or supply
   all three `ZOLANA_*` URLs.

Run from the repository root.

```sh
just setup build-ts
npx --yes pnpm@9.15.0 --filter spr-tvc-typescript-client-example example
```

The signer uses Turnkey raw Ed25519 signing for off-chain approvals and
Turnkey Solana transaction signing for on-chain transactions. It verifies
each signature against the expected account and bytes. The derivation
signature used for the local shielded wallet is key material.

## Localnet

`just headless-e2e` runs the same deposit, claim, and sweep with local signers. It needs a sibling `zolana` checkout. The [CI workflow](../../.github/workflows/headless-local-e2e.yml) lists the toolchain.
