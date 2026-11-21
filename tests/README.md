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

Use two test EIFs commissioned according to the [native runbook](../enclave/deploy/nitro/README.md).
In a scratch directory write `a-pin.json` and `b-pin.json` with each release ID,
executable SHA-256, custody epoch and independently derived PCR0–PCR3 in the policy's target
format. Put the shared security domain and note seed commitment in
`inputs.json` as `domain` and `seed`. Use only synthetic notes and test keys.

```sh
pnpm --filter spr-tvc-typescript-client-example exec tsx ../tests/nitro/rehearsal.mts \
  http://127.0.0.1:55441/ "$scratch" http://127.0.0.1:55442/
```

Use epoch 1 for A and a distinct rotated custody epoch for B to exercise revocation.
The script signs and serves a test policy locally. Once it writes `note-created`,
verify that both enclaves are healthy and create `move-ready`. Once it writes
`before-retire`, stop A and create `old-retired`. It verifies the original note
again under B, then rejects a stale policy and a higher sequence that tries to lower the
recorded custody floor.
