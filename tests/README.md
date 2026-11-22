# Running the tests

`just ci` runs Rust and TypeScript suites, including the SDK-to-enclave
loopback test. Run `just decryption-e2e` to repeat that test on its own.
Rust and TypeScript tests live under each component's `tests/`.
See the [invariants](INVARIANTS.md) and [internal audit](AUDIT.md).

`just headless-e2e` adds the local Solana validator, indexer, and prover.
Use a sibling `../zolana` checkout, or set `ZOLANA_DIR`. CI builds
`c5297afa13e8bfb6edadf6408304ef3fc2f8c676`, which includes the process
ownership support used for cleanup. The run owns its ledger and service
processes. The loopback enclave binds an ephemeral port and publishes it to
the test. Pass a port offset to run another Solana localnet.

## Live Nitro upgrade

For an on-chain rehearsal, start with a canonical devnet policy containing
only the old epoch. Use a funded devnet fee payer and the approved native
wallet trust bundle. The example creates a fresh recipient and looks up its
public keys before the recipient authorizes anything.

```sh
pnpm build:ts
API_KEY="$devnet_api_key" EXAMPLE_ACCEPT_PUBLIC_RECIPIENT=1 \
TVC_SOLANA_KEYPAIR_PATH="$payer" NITRO_WALLET_TRUST="$wallet_trust" \
NITRO_CHECKPOINT_PATH="$checkpoint" NITRO_REPLACEMENT_EPOCH=2 \
pnpm --filter spr-tvc-typescript-client-example example
```

Use absolute file paths and a new checkpoint file for each rehearsal. Wait
for the confirmed transfer printed by the example before promoting the new
epoch. Raise the live wallet policy floor to the replacement epoch and stop
the old replica. The example waits up to five minutes, opens the recipient
through the new epoch, verifies the transfer amount, and sweeps the note to
the recipient's own privacy keys. It checks that the recipient remains
unregistered and holds no public SOL throughout the run.

### Synthetic recovery drill

Use two test EIFs commissioned according to the [native runbook](../enclave/deploy/nitro/README.md).
In a scratch directory write `a-pin.json` and `b-pin.json` with each release ID,
executable SHA-256, custody epoch, canonical custody digest and independently
derived PCR0–PCR3 in the policy's target format. Put the shared security domain and note seed commitment in
`inputs.json` as `domain` and `seed`. Use only synthetic notes and test keys.

```sh
pnpm --filter spr-tvc-typescript-client-example exec tsx ../tests/nitro/rehearsal.mts \
  http://127.0.0.1:55441/ "$scratch" http://127.0.0.1:55442/
```

Use epoch 1 for A and a distinct rotated custody epoch for B to exercise revocation.
The script signs policies and serves both publisher responses locally. Once it writes `note-created`,
verify that both enclaves are healthy and create `move-ready`. Once it writes
`before-retire`, stop A and create `old-retired`. It verifies the original note
again under B. A fresh wallet must select the promoted release while one publisher
replays the previous revision. The script also checks a lower custody floor and
a replay against a persisted checkpoint.
