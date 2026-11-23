# Enclave releases

Install dependencies once with `just setup`. Log `tvc` into the app's
organization, or set `TVC_ORG_ID`, `TVC_API_KEY_PUBLIC`, and
`TVC_API_KEY_PRIVATE`. Install [crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane)
(`brew install crane` on macOS). `xtask` uses it to export the pinned
image from the registry and hashes `/tvc_app` with `tar` and `sha256sum`.
The SDK verifies live attestation.

## Deploy a release

For a new Turnkey app, set its app ID, ingress URL, security domain ID,
and Quorum key ID, epoch, and public key in `networks.devnet` in
[release.json](../enclave/deploy/release.json).

To stage an existing build, pass the ID of its successful
[publish run](https://github.com/helius-labs/spr-tvc/actions/workflows/publish-enclave-image.yml).

```sh
cargo xtask deploy rehearsal-01 --network devnet --run 44763261846 --replicas 1
```

On a fresh devnet app configured with the same two hosted operators in its
2-of-2 manifest and share sets, add `--activate` to review, provision, and
pin in the same command. Run `just build-ts` first for live verification.
`tvc` prompts for each missing manifest review in your terminal. After
both reviews, `xtask` waits for verified provisioning details, provisions
the two shares, waits for the target replicas and ingress to become ready,
and verifies the Boot Proof before writing the SDK pin. Rerun `deploy`
with the same release ID and `--activate` to resume.

For a new build from `main`, use `--publish`. Approve the GitHub
`image-publish` job from the URL printed by `xtask`. If you interrupt the
wait, use that run ID with `--run` after the publish succeeds.

```sh
cargo xtask deploy rehearsal-02 --network devnet --publish --replicas 1
```

You can also pass the exact `tag@sha256:…` reference with `--image`. Omit
`--replicas` to use Turnkey's default. Replica count is independent of
operator thresholds.

`deploy` measures `/tvc_app`, writes the descriptor, submits a candidate,
and verifies the image, executable, launch arguments, and Quorum key.
Rerun `deploy` with the same release ID and network to resume a recorded
candidate. If Turnkey submission was interrupted before its ID was saved,
check Turnkey before retrying.

For mainnet, use a separate app and ingress. Pass `--network mainnet` and
`--source-commit "$commit"` with the full reviewed SHA. `xtask` verifies
the pinned image's provenance from protected `main`.

For manual activation, each operator reviews the manifest with
`tvc deploy approve --deploy-id "$id"`.
Select an operator in the manifest set with `--operator-id "$operator"` for
a hosted key, `--operator-seed-path "$seed_file"` for a local key, or
`--serial "$serial"` for a YubiKey. Once the approval threshold is met,
use `tvc deploy provision --deploy-id "$id" --operator-id "$operator"` for
a hosted share. For a local share, use `tvc deploy provisioning-details`,
`tvc keys re-encrypt-local-share`, and `tvc deploy post-share` from the
operator's machine. Keep operator seeds and encrypted share metadata
outside the checkout.

Check readiness with `tvc deploy get-status --deploy-id "$id"`. An app's
first deployment becomes live when ready. On an existing devnet app, an
operator selects a ready deployment with `tvc app set-live-deploy --deploy-id "$id"`.

## Pin devnet

Build the SDK with `just build-ts` before live verification.

```sh
cargo xtask pin "$release" --network devnet
```

Run this after the endpoint serves the staged deployment. The tool checks the
live deployment and Boot Proof before signing with a one-time devnet
authority and writing `sdk/releases/devnet.json`. Record the deployment and
pin together. Build the TypeScript SDK with `just build-ts` and run the
[hosted example](../example/README.md) separately for a funded devnet rehearsal.

Discovery and ping responses are capped at 64 KiB each. Discovery has 10
seconds. A single 30-second deadline covers ping, Boot Proof lookup, and
attestation verification. Cargo terminates a release check subprocess that
is still running after 60 seconds.

## Mainnet

Use independently held operator keys and a threshold for both manifest
approval and share recovery.
Configure the app, Quorum key, and domain in `networks.mainnet` in
[release.json](../enclave/deploy/release.json). Pin the same
`quorumPublicKey` and `securityDomainId`, approved `qosIdentityPcrs`
(PCR0–3), and `maximumPolicyLifetimeMs` in `sdk/trust/mainnet.json`.
Use the deployed QOS release's published `nitro.pcrs` for PCR0–2.
Turnkey's [QOS 0.12.1 release](https://github.com/tkhq/qos/releases/tag/qos_core-v0.12.1)
publishes matching PCR0 and PCR1. Pin PCR3 separately for the intended
deployment's parent IAM role. [AWS Nitro PCRs](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html)

`releaseAuthorities` holds `authoritySetId`, `minimumRevocationEpoch`,
`threshold`, and `keys` as `{keyId, publicKey}` entries. The threshold
requires at least two distinct keys.

The current QOS dependency still brings an affected `crypto-bigint` into
Quorum operations and pins `libc` below the version required by patched
Tokio. Resolve both before provisioning production keys.
[RustSec crypto-bigint advisory](https://rustsec.org/advisories/RUSTSEC-2026-0387.html)
· [RustSec Tokio advisory](https://rustsec.org/advisories/RUSTSEC-2026-0386.html)

Build the SDK with `just build-ts`. When the candidate is live, run:

```sh
cargo xtask prepare "$release" --network mainnet --source-commit "$commit"
cargo xtask pin "$release" --network mainnet --source-commit "$commit" --signed-policy "$signed_policy"
```

Between those commands, independent authorities review the policy request
and sign its digest using P-256 with prehashed input. The signed JSON holds
`policy`, `authoritySetId`, and `signatures`. Each signature entry holds
`keyId` and a lowercase hex 64-byte raw low-S `signature`.
`pin` rechecks attestation and threshold signatures before writing
`sdk/releases/mainnet.json`. Distribute the reviewed pin with its matching
service endpoint.

### Recovery and exposure

- Keep the previous approved ingress during rollout. To roll back, route
  clients there with a valid policy at the current epoch or get fresh
  signatures for that release.
- Rehearse restoring the same Quorum key in an approved enclave. Use it to
  claim and sweep a note that predates the outage. Rotating the key requires
  keeping the old service available while recipients sweep.
- Revoke with a higher `minimumRevocationEpoch` in the independently
  distributed trust config. Clients apply the new floor after updating.
  Until then, they can accept policies through their signed expiry.
- Enforce funded canary limits at deposit or transfer admission. Sender
  wallets can reuse service public keys without contacting the enclave.
- Before funding, verify send, claim, sweep, and withdrawal on the approved
  deployment. Independent review must cover the deployed Solana programs,
  circuits, verification keys, prover, wallet signing policy, and upgrade
  authorities.
