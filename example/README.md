# Direct Turnkey example

The example uses a Turnkey-managed Solana account to sign transactions and
decrypt approvals. It deposits SOL, sends to the address's service keys,
claims the note, then sweeps it into the account's locally derived shielded
wallet.

## Devnet

1. Create or select a funded Turnkey Solana account with no SPR registry record.
2. Copy [`client.env.example`](client.env.example) to `.env` in this directory.
   Fill in the wallet's Turnkey credentials and the decryption app's
   separate Boot Proof credentials.
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

`just headless-e2e` runs the same flow with local Solana signers and the
loopback decryption testkit. It needs a sibling `zolana` checkout and the
toolchain described by the [CI workflow](../.github/workflows/headless-local-e2e.yml).
`just decryption-e2e` exercises signed decrypt batches and commitment checks
without a Solana validator.
