# Running the tests

`just ci` runs Rust and TypeScript suites, including the SDK-to-enclave
loopback test. Run `just decryption-e2e` to repeat that test on its own.
Rust and TypeScript tests live under each component's `tests/`.
See the [invariants](INVARIANTS.md) and [internal audit](AUDIT.md).

## Guarded payments with packed SDKs

Run `just headless-e2e` with a sibling `../zolana` checkout, or set
`ZOLANA_DIR`. Install npm dependencies in that checkout with `npm ci`.
The [CI workflow](../.github/workflows/headless-local-e2e.yml) pins the
Privacy Rings revision and shows the required toolchain. Pass a port offset
to run a second localnet.

The job packs both SDKs and type-checks a consumer that installs them together.
It builds the on-chain programs from the same Privacy Rings checkout as the
wallet SDK. The test checks the signed registry assertion, pays an unfunded
recipient, rejects a second payment when the recipient registers during signing,
then uses the standalone loopback service to recover and sweep the first note.
It checks both wallet balances at the finalized sweep slot.

## Live Nitro upgrade

For an on-chain rehearsal, start with a canonical devnet policy containing
only the old epoch. Use a funded devnet fee payer, the approved native
wallet trust bundle and a fresh devnet keypair for the recipient. Keep the
recipient keypair in a private directory outside the checkout. The same signer
can authorize recovery of the note if the rehearsal process exits after the
transfer. Leave this account unfunded and unregistered.

This canary uses the published wallet SDK to qualify custody and recovery.
Repeat the [wallet localnet registry assertion cases](https://github.com/helius-labs/privacy-rings/pull/652)
on devnet after deploying the registry upgrade.

```sh
solana-keygen new --silent --no-bip39-passphrase --outfile "$recipient_keypair"
pnpm build:ts
API_KEY="$devnet_api_key" EXAMPLE_ACCEPT_PUBLIC_RECIPIENT=1 \
TVC_SOLANA_KEYPAIR_PATH="$payer" NITRO_RECIPIENT_KEYPAIR_PATH="$recipient_keypair" \
NITRO_WALLET_TRUST="$wallet_trust" \
NITRO_CHECKPOINT_PATH="$checkpoint" NITRO_REPLACEMENT_EPOCH=2 \
pnpm --filter spr-tvc-typescript-client-example example
```

Use absolute file paths and a new checkpoint file for each rehearsal. The
example validates both trust files when testing a seed cutover. Before
depositing, it resolves the recipient without their signature and checks that
both buckets serve the policy it accepted for the original epoch. It rechecks
the recipient and signed policy after signing, before sending. Wait for the
finalized transfer, stop the old replica, then publish the replacement custody
floor to both buckets. The example waits up to five minutes for both buckets
to serve the accepted policy with targets only at the requested replacement
epoch. It checks that the
recipient's viewing and nullifier public keys match their pre-rotation
values and recovers the transferred amount. Before proving the sweep and again
after signing it, the example checks that both published heads and its local
checkpoint still match the policy used to qualify the replacement. The
recipient remains unregistered and holds no public SOL.

To tie the claim to the post-retirement cold boot, set
`NITRO_RETIREMENT_REPORT` to a new absolute path. Run the canary and
`verify-retired` on the same clock-synchronized operator host. After the
canary logs its finalized transfer, follow the
[retirement procedure](../enclave/deploy/nitro/README.md#rotate-custody-and-activate-releases).
Use a separate canary transfer for the check before scheduling key deletion.
Pass the canary's path to `verify-retired --output` in a directory
controlled by the operator. The canary waits up to one hour for the verified
report. It checks that the S3 closure was published after transfer finality
for the original domain, epoch and custody digest. It recovers the note
through the exact replacement custody record, signed policy and attested boot
in the report.
It logs the boot key ID alongside the transfer and sweep signatures.

## Live seed cutover

Prepare two devnet seed domains with separately initialized seeds and approved
wallet trust files. Start with the old domain serving an ordinary activation.
Run the command above with `NITRO_REPLACEMENT_TRUST="$new_wallet_trust"` in
place of `NITRO_REPLACEMENT_EPOCH`. Use a fresh checkpoint file. After the
transfer finalizes, publish the recovery-only successor to both old-domain
buckets and activate the new domain. Keep the old recovery replicas running.
The example waits for both policy pairs to agree. It checks that the original
payment client rejects lookup and saves the accepted recovery-only checkpoint.
The new domain returns different viewing and nullifier keys
for the same recipient. It then opens the old note and sweeps it to the
recipient's wallet-local keys. Before proving and sending the sweep, it
rechecks the agreed published policy and checkpoint in each domain. After
finality it syncs both wallets and verifies that the source note was spent
and the destination opened the expected note.

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
