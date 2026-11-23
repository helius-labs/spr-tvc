# Enclave releases

Run `just setup build-ts` from the repo root. Log `tvc` into the app's
organization, or set `TVC_ORG_ID`, `TVC_API_KEY_PUBLIC`, and
`TVC_API_KEY_PRIVATE`. The tool uses Docker to read the executable digest
and the SDK to verify live attestation.

## Stage a release

Run the [image publisher](../.github/workflows/publish-enclave-image.yml)
and take the image reference from its summary. Set `release` to a new
release ID, `image` to that reference, and `network` to `devnet` or
`mainnet`.

```sh
cargo xtask describe "$release" --network "$network" --image "$image"
cargo xtask stage "$release" --network "$network"
```

Add `--source-commit "$commit"` to every mainnet invocation. The commit
is the full reviewed SHA from the publisher. The tool verifies provenance
from protected `main` for the exact image digest.

`describe` writes the deployment JSON and records the SHA-256 of
`/tvc_app`. `stage` creates the deployment or resumes the recorded ID.
It checks the image digest, measured executable and launch arguments, and
Quorum key before operators approve or provision. Turnkey can return a
digest-only image reference, so the check accepts that canonical form
when its repository and digest match. Mainnet candidates use a separate
app and ingress.

Before submitting a create, `stage` records the organization and validated
descriptor digest in the local deployment record. It allows 60 seconds for
the Turnkey CLI. If the response is interrupted, find the resulting ID in
Turnkey and recover it from the same release and checkout.

```sh
cargo xtask stage "$release" --network "$network" --deployment-id "$id"
```

Recovery verifies the deployment before recording its ID. A plain rerun
resumes a recorded ID. If Turnkey confirms that creation failed, use a new
release ID for a new attempt.

Operators review and approve with `tvc deploy approve --deploy-id "$id"`.
For a hosted share use `tvc deploy provision --deploy-id "$id" --operator-id "$operator"`.
For a locally held share, use `tvc deploy provisioning-details`,
`tvc keys re-encrypt-local-share`, and `tvc deploy post-share` from the
operator's machine. Keep operator seeds and encrypted share metadata
outside the checkout.

Check readiness with `tvc deploy get-status --deploy-id "$id"`. An app's
first deployment becomes live when ready. On an existing devnet app, an
operator selects a ready deployment with `tvc app set-live-deploy --deploy-id "$id"`.

## Pin devnet

```sh
cargo xtask pin "$release" --network devnet
```

Run this after the endpoint serves the staged deployment. The tool checks the
live deployment and Boot Proof before signing with a one-time devnet
authority and writing `sdk/releases/devnet.json`. Record the deployment and
pin together.

Discovery and ping responses are capped at 64 KiB each. Discovery has 10
seconds. A single 30-second deadline covers ping, Boot Proof lookup, and
attestation verification. Cargo terminates a release check subprocess that
is still running after 60 seconds.

## Mainnet

Use independently held operator keys and a threshold for both manifest
approval and share recovery.
Configure the app, Quorum key, and domain in
[release.json](../enclave/deploy/release.json) and
`enclave/deploy/mainnet/spr-decryption-service-mainnet.app.json`. Pin the
same `quorumPublicKey` and `securityDomainId`, approved `qosIdentityPcrs`
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

After the candidate passes live discovery, run:

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
