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
the test. The sender registers before paying an unregistered recipient. The
recipient then registers wallet-local keys, opens the earlier note with the
service, and sweeps it. The payer funds the transactions and the recipient
keeps no public SOL. Pass a port offset to run another Solana localnet.

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

Use absolute file paths and a new checkpoint file for each rehearsal. The
example checks that both buckets serve the policy it accepted for the original
epoch after resolving the address and again before sending. Wait for the
confirmed transfer, stop the old replica, then publish the replacement custody
floor to both buckets. The example waits up to five minutes for both buckets
to serve the accepted policy with targets only at the requested replacement
epoch. It checks that the
recipient's viewing and nullifier public keys match their pre-rotation
values and recovers the transferred amount. Before proving and sending the
sweep, it checks that both published heads and its local checkpoint still
match the policy used to qualify the replacement. The recipient remains
unregistered and holds no public SOL.

To tie the claim to the post-retirement cold boot, set
`NITRO_RETIREMENT_REPORT` to a new absolute path. Run the canary and
`verify-retired` on the same clock-synchronized operator host. After the
canary logs its confirmed transfer, follow the
[retirement procedure](../enclave/deploy/nitro/README.md#rotate-custody-and-activate-releases).
Use a separate canary transfer for the check before scheduling key deletion.
Pass the canary's path to `verify-retired --output` in a directory
controlled by the operator. The canary waits up to one hour for the verified
report. It checks that the S3 closure was published after transfer confirmation
for the original domain, epoch and custody digest. It recovers the note
through the exact replacement custody record, signed policy and attested boot
in the report.
It logs the boot key ID alongside the transfer and sweep signatures.

## Live seed cutover

Prepare two devnet seed domains with separately initialized seeds and approved
wallet trust files. Start with the old domain serving an ordinary activation.
Run the command above with `NITRO_REPLACEMENT_TRUST="$new_wallet_trust"` in
place of `NITRO_REPLACEMENT_EPOCH`. Use a fresh checkpoint file. After the
transfer confirms, publish the recovery-only successor to both old-domain
buckets and activate the new domain. Keep the old recovery replicas running.
The example waits for both policy pairs to agree. It checks that old payment
lookup fails and the new domain returns different viewing and nullifier keys
for the same recipient. It then opens the old note and sweeps it to the
recipient's wallet-local keys. Before proving and sending the sweep, it
rechecks the agreed published policy and checkpoint in each domain.

## Synthetic recovery drill

Use two test EIFs commissioned according to the [native runbook](../enclave/deploy/nitro/README.md).
In a scratch directory write `a-pin.json` and `b-pin.json` with each release ID,
executable SHA-256, custody epoch, canonical custody digest and independently
PCR0–PCR4 from each registered target's `attestation-pins` output. Put the shared security domain and note seed commitment in
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
