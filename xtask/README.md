# Enclave releases

A release is three workflow runs and the operator signatures between them.
`image-publish` protects every run. The Turnkey API key for that environment
is `TVC_ORG_ID`, `TVC_API_KEY_PUBLIC`, and `TVC_API_KEY_PRIVATE`. That key
creates a deployment and reads it. It does not approve a manifest or hold a
Quorum share.

## Publish

Dispatch [publish-enclave-image](../.github/workflows/publish-enclave-image.yml)
for `devnet` or `mainnet`. Mainnet runs only from protected `main`. The job
pushes the image, attests the digest, and records the reference, the
`/tvc_app` hash, and the source commit. It does not touch Turnkey.

## Deploy

Dispatch [deploy-enclave](../.github/workflows/deploy-enclave.yml) with that
image reference and the full source commit. The job checks the tag, and on
mainnet the attestation from protected `main`. It hashes `/tvc_app`, creates
the deployment from
[release.json](../decryption-service/deploy/release.json), and exits with the
deploy id. The deployment is not live.

Pass the deploy id back to resume a deployment whose manifest was not ready
on the first run. A mainnet app that is already serving a different
deployment is rejected. Keep the previous mainnet ingress on its own app.

## Operators

Each operator, from their own key, approves the manifest and posts their
share of the Quorum key. Mainnet needs a threshold of at least 2 for both.

```sh
tvc deploy approve --deploy-id "$id" --operator-id "$operator"
tvc deploy provision --deploy-id "$id" --operator-id "$operator"
```

For a locally held share, use `tvc deploy provisioning-details`,
`tvc keys re-encrypt-local-share`, and `tvc deploy post-share` from the
operator's machine. Keep operator seeds and encrypted share metadata
outside the checkout.

Check readiness with `tvc deploy get-status --deploy-id "$id"`. An app's
first deployment becomes live when ready. On an existing devnet app, an
operator selects a ready deployment with `tvc app set-live-deploy --deploy-id "$id"`.

## Pin

Dispatch [pin-enclave](../.github/workflows/pin-enclave.yml) after that deploy
id is live. The job reads `/v1/info` and the Boot Proof and checks the image,
the executable, the launch arguments, the Quorum key, the manifest-set
approvals, and PCR0–3.

On devnet it signs with a one-time key and opens a pull request that writes
`client/sdk/releases/devnet.json`. Merging that pull request is what points
devnet clients at the enclave.

On mainnet it uploads `policy-request.json`. The release authorities sign
that digest using P-256 with prehashed input. The signed JSON holds
`policy`, `authoritySetId`, and `signatures`. Each signature entry holds
`keyId` and a lowercase hex 64-byte raw low-S `signature`. Commit that file
as `client/sdk/releases/mainnet.json`. The pull request runs the live check
again and checks the signatures against `client/sdk/trust/mainnet.json`. The
workflow cannot change the Quorum key, the PCRs, the security domain, the
authority set, or the lifetime.

The manifest nonce floor starts at zero. Pass `minimum_manifest_nonce` on a
later pin to drop older manifests. A client that has not taken that update
stops accepting an old image when that deployment is shut down.

Discovery and ping responses are capped at 64 KiB each. Discovery has 10
seconds. A single 30-second deadline covers ping, Boot Proof lookup, and
attestation verification. Cargo terminates a release check subprocess that
is still running after 60 seconds.

## Mainnet

Use independently held operator keys and a threshold for both manifest
approval and share recovery.
Configure the app, Quorum key, and domain in
[release.json](../decryption-service/deploy/release.json) and
`decryption-service/deploy/mainnet/spr-decryption-service-mainnet.app.json`. Pin the
same `quorumPublicKey` and `securityDomainId`, approved `qosIdentityPcrs`
(PCR0–3), and `maximumPolicyLifetimeMs` in `client/sdk/trust/mainnet.json`.
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
