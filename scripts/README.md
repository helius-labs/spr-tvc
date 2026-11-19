# Operator tooling

## Release

Build the TypeScript client with `just setup build-ts` and log the Turnkey
`tvc` CLI (0.19.0 or later) into the decryption app's organization. Docker
must be able to run the published `linux/amd64` image.

[The release config](../enclave/deploy/release.json) pins the
hosted runtime's QOS version and PCR0–3. Cargo independently pins the QOS
library that the application links. Run `publish-enclave-image` for the
network, then use the digest-pinned reference from its summary.

```sh
just release devnet decryption-service-devnet-<commit> --image <reference> \
  --operator-seeds <dir> --quorum-key-metadata <file>
```

The operator seed directory uses `operator-<n>.seed` for the n-th operator
in the release config. The Quorum key metadata contains the encrypted shares.
Keep the seed files and metadata outside the checkout. The CLI prompts for
manifest review during approval and local share re-encryption. Devnet's
`--unattended` skips the prompts and retains verification.

| Phase | What it does |
| --- | --- |
| `build` | Checks the image's network tag, records its digest and the SHA-256 of `/tvc_app`, and writes a deployment descriptor. |
| `deploy` | Creates the deployment, collects approvals, provisions shares, sets the release live, and waits for matching discovery. A retry resumes from the deployment record. |
| `policy` | Reads the recorded live deployment's manifest through the authenticated Turnkey API, checks it against the local build digest and app Quorum key, and verifies the live Boot Proof before signing the SDK pin. |

Run an individual phase with
`node scripts/release.mjs <phase> <release-id> --network devnet`.
Commit the deployment records and the signed v2 pin under `sdk/releases/`. Turnkey allows three
deployments per application. The explicit `--prune-deployments` flag can
remove older inactive deployments to make room.

## Tests

`with-local-decryption.sh` runs a command against the loopback testkit.
`start-localnet.sh` starts the Solana validator, indexer, and prover for
`just headless-e2e`.
