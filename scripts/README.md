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
Commit the deployment records and the signed pin under `sdk/releases/`. Turnkey allows three
deployments per application. The explicit `--prune-deployments` flag can
remove older inactive deployments to make room.

## Tests

`with-local-decryption.sh` runs a command against the loopback testkit.
`start-localnet.sh` starts the Solana validator, indexer, and prover for
`just headless-e2e`.

## Mainnet

The default release command combines phases on devnet. Mainnet uses a
separate Turnkey app and ingress for each release candidate. A serving
app keeps its previous deployment while clients move to the new
ingress and signed pin.

Before the first release, configure the mainnet app, security domain, and
operator IDs in `enclave/deploy/release.json` and put the app descriptor in
`enclave/deploy/mainnet/decryption-service-mainnet.app.json`. Use a separate
mainnet Quorum key. Set threshold manifest approval and share recovery with
separate operators. Keep private keys and shares outside the repository.

Under `sdk/trust/mainnet.json`, pin `securityDomainId`, `quorumPublicKey`,
`qosIdentityPcrs`, `maximumPolicyLifetimeMs`, and `releaseAuthorities`.
The authority set holds `authoritySetId`, `minimumRevocationEpoch`,
`threshold`, and an array of `{keyId, publicKey}` entries. Mainnet requires
at least two distinct public keys. The privacy program and auditor review
should determine the maximum policy lifetime and key domain before funding.

1. Publish the mainnet image from protected `main`. Record the reported
   source commit and immutable image reference. `build`, `deploy`, and the
   policy phases check the published image's attestation against that commit.
2. Run `build` and `deploy` using
   `node scripts/release.mjs <phase> <release-id> --network mainnet --source-commit <sha>`.
   Add `--image <reference>` on build. The deploy phase creates the candidate and
   checks its manifest, including both Quorum thresholds. Operators independently
   review and approve the manifest with `tvc deploy approve` and provision their
   shares using the Turnkey CLI. Once Turnkey serves the app's first deployment,
   run `prepare` with the same arguments. It verifies the candidate's attestation
   and writes the policy request with its signing digest.
3. Independent authorities review and sign that digest as P-256 with
   prehashed input. Collect a JSON object with `policy`, `authoritySetId`,
   and `signatures`. Each signature is `{keyId, signature}` with a 64-byte raw
   low-S signature encoded in hex. Do not hash the digest a second time.
   Run `policy` with the same release ID and commit and
   `--signed-policy <file>`. It rechecks attestation and the signatures before
   writing `sdk/releases/mainnet.json`.
4. Review the resulting pin and deploy it with the matching endpoint in the
   consuming application. Verify live send, claim, sweep, and withdrawal
   along the exact program and prover paths before accepting funded traffic.

### Recovery and exposure

- Rehearse restoration of the same Quorum key into an approved recovery
  enclave. Verify the restored public lookup and claim and sweep a note
  created before the simulated outage. Record how long the flow takes.
- Keep the original ingress available during rollout. Roll back by routing to
  the previous approved ingress with a policy for that release that is still
  valid and authorized at the current epoch, or by obtaining fresh signatures
  for it. The release tool refuses in-place mainnet activation and pruning.
- For revocation, raise `minimumRevocationEpoch` in the independently
  distributed trust configuration. Roll out that change and rotate the
  consuming application's routing and pins. Older clients honor their old
  policies until they update or those policies expire. Rehearse this window
  using the configured maximum policy lifetime.
- Quorum key rotation requires a separate recipient migration. Retain the
  old key in an approved service while recipients sweep. A successful
  promotion or a fresh pin does not recover notes after key loss.
- Set funded canary limits at deposit or transfer admission and monitor the
  value of unswept notes by domain. Limiting requests to this service cannot
  cap exposure because senders can reuse previously fetched public keys.

Mainnet launch also requires independent review of the deployed Solana
programs, circuits and verification keys, prover, wallet signing policy,
and upgrade authorities. A local test run covers the release checks but
cannot substitute for the custody and production recovery drills.
