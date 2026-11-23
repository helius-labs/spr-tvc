# Running the tests

`just ci` runs Rust and TypeScript suites, including the SDK-to-enclave
loopback test. Run `just decryption-e2e` to repeat that test on its own.
Rust and TypeScript tests live under each component's `tests/`.
See the [invariants](INVARIANTS.md).

## Guarded payments with packed SDKs

Run `just headless-e2e` with a sibling `../zolana` checkout, or set
`ZOLANA_DIR`. Install npm dependencies in that checkout with `npm ci`.
The [CI workflow](../.github/workflows/headless-local-e2e.yml) pins the
Privacy Rings revision and shows the required toolchain. Pass a port offset
to run a second localnet.

The job packs both SDKs and type-checks a consumer that installs them together.
It builds the shielded pool and user registry from the same Privacy Rings
checkout as the wallet SDK. The test checks the signed registry assertion,
pays an unfunded recipient, rejects a second payment when they register during signing,
then uses the standalone loopback service to recover and sweep the first note.
It checks both wallet balances at the finalized sweep slot.
