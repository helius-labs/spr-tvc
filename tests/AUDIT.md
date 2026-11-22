# Native Nitro internal audit and external handoff

Scope includes the native enclave, the common owner-signature and note-opening code, the native SDK verifier, release signing, key policies, provisioning and the rollout runbook. The existing hosted QOS release path stays separate. The review covered source, protocol fixtures, AWS documentation, dependency advisories, local tests and a disposable AWS rehearsal. It established implementation evidence for the invariants below. An independent security reviewer still needs to validate the design and deployed configuration before mainnet funding.

## Findings addressed

| ID | Finding | Fix and evidence |
| --- | --- | --- |
| N-01 | The prototype placed an entire seed under a single KMS key, and a KMS key administrator could widen that policy. | Six separate accounts hold encrypted shares. Three distinct valid shares open the seed. Each wrapping policy is sealed, with precise role, context and PCR0–PCR3 checks. A measured rotation issues fresh shares for new custodian keys while preserving the stable seed commitment. The custody floor prevents later policies from reactivating a retired epoch. [Provisioning](../enclave/src/nitro.rs) · [KMS policy](../enclave/deploy/nitro/kms_policy.py) · SPR-NITRO-01–04, SPR-NITRO-10–12 |
| N-02 | A static prototype PCR pin had no release quorum, expiry or rollback protection. A client could trust a substituted policy after an upgrade. | The publisher requires a signed successor and live enclave attestation before updating the canonical policy. The SDK persists its checkpoint before sending wallet operations. [Policy verifier](../sdk/src/attestation/nitro-policy.ts) · [Conditional publisher](../xtask/nitro-publish.ts) · SPR-NITRO-05–06, SPR-NITRO-13–15 |
| N-03 | A load balancer could send discovery and attestation to different boot keys. There was no multi-target routing plan. | Discovery and evidence return in one response. Its nonce, discovery digest and replica key are authenticated. The SDK maintains one attested endpoint per session, checks operation signatures against that boot and can select another authorized endpoint on its next session. [Client](../sdk/src/client/nitro.ts) · SPR-NITRO-07–08 |
| N-04 | The native verifier shared the hosted verifier's certificate-chain behavior. Its trust assumptions and validity checks needed independent coverage. | Native verifies the ordered AWS path under the exact root, certificate validity, basic constraints and usages, and the ES384 COSE signature. The fixture comes from a disposable AWS enclave with a known nonce, measurements and verifier time. [AWS verifier](../sdk/src/attestation/aws-nitro.ts) · [Evidence tests](../sdk/tests/attestation/nitro-evidence.test.ts) |
| N-05 | The native dependency graph contained affected `crypto-bigint 0.5.5` through `qos_p256` and Tokio 1.48 through the hosted QOS workspace resolution. | Build the native artifact with the dedicated manifest and lock. The enclave uses OpenSSL primitives for the existing P-256 envelope and Tokio 1.54.1 for the runtime. The Rust interop test and live SDK verify wire compatibility. CI checks the production dependency graph. [Native manifest](../enclave/native/Cargo.toml) · [Wire test](../enclave/tests/unit/nitro_wire.rs) · [RustSec crypto-bigint](https://rustsec.org/advisories/RUSTSEC-2026-0387.html) · [RustSec Tokio](https://rustsec.org/advisories/RUSTSEC-2026-0386.html) |
| N-06 | A single S3 publisher could replay a still-valid signed policy to a fresh or restored wallet. | Wallets authenticate the policies from two pinned independent AWS accounts. Once both publish a revision, one publisher can interrupt service but cannot move the wallet to an older policy. A single signed successor can serve traffic during a rollout. Retirement requires both publishers to agree before and after replacement attestation. [Policy and retirement tests](../sdk/tests/attestation/nitro-policy.test.ts) · [Client tests](../sdk/tests/client/nitro.test.ts) |

## Remaining qualification and review

| ID | Scope | Required evidence |
| --- | --- | --- |
| Q-01 | Custody admission and ledger | Exercise the two approval keys, six independent recovery accounts, the separate host and the write-once ledger in AWS. Verify actual IAM denies for wrong roles, contexts, PCRs and direct unmeasured access. Race two legitimate publications and verify eviction or overwrite attempts fail. Prove a cold boot after retirement from three current custodians. Local tests use mocked AWS responses. The earlier live rehearsal used one AWS account. |
| Q-02 | Wallet trust distribution and freshness | Integrate both policy bucket pins, signer keys and minimum sequence in the supported wallet entry points. Exercise checkpoint races, restart, crash consistency and restore. Prove the actual publishers cannot write or assume roles in each other's account. Rehearse a partial rollout, replay at one bucket, outage, and emergency pin update. Both publishers serving the same old policy remains a trust failure if the wallet's checkpoint, pins and deadline allow it. |
| Q-03 | Release pipeline and fleet | The [devnet dispatch](https://github.com/helius-labs/spr-tvc/actions/runs/44963865368) built and attested an EIF. The operator verifier accepted the downloaded artifact for exactly the reviewed ref and commit, and refused the bundle when presented as `main`. Exercise the protected mainnet job separately and independently validate its build inputs and measurements. Qualify S3 publication, browser CORS, TLS ingress, rate limits, logs, target isolation, failover, capacity and certificate rotation on a long-running devnet fleet. The production infrastructure and signer roles are outside this worktree. |
| Q-04 | Mainnet and migration | The checked-in hosted SDK [release](../sdk/releases/mainnet.json) and [trust](../sdk/trust/mainnet.json) are both empty. The successful hosted publication runs checked on `main` produced devnet tags. Confirm Turnkey and wallet routing history before replacing a seed domain. If any notes depend on an old domain, retain access or use an owner-authorized sweep. Run the [native devnet example](README.md#live-nitro-upgrade) across rotation. The earlier AWS drill used synthetic notes. |
| Q-05 | External security review | Review crypto and secret lifetimes, independent custodians' backups, policy replay windows, AWS roles and runtime measurements against the deployable commit. Reproduce the checks below and disposition any remaining dependency and platform risks. Require reviewer sign-off before accepting mainnet funds. |
| Q-06 | Historical custody verification | Rehearse exporting a committed receipt and its digest, replacing custody approval keys, disabling retired signing keys, and verifying the archived receipt with the pinned trust schedule. Local tests use real P-256 signatures with KMS unavailable. |

## 3-of-6 custody rehearsal

A disposable AWS Nitro host ran four measured images in sequence. The genesis
enclave produced six RSA KMS recovery packages, and the operator verified the
receipt with fresh Nitro evidence. The first serving enclave opened a synthetic
note after three custody shares passed the measured KMS unwrap. The rotation
enclave accepted three old shares and issued a new epoch to six keys, including
one replacement custodian key. The replacement serving enclave booted from
three new shares and opened the original note with the same wallet keys.

The boot and rotation targets refused submissions with two or duplicated
shares. The wallet verified the new epoch and refused a higher-sequence
policy that lowered its recorded custody floor. The actual KMS keys used for
the drill were in one disposable account. The production six-account role
and custody ceremony still need independent qualification. The rehearsed
devnet executable SHA-256 was `186089a9c485ccb8fab4ad99a5bd463f97546f15ee1c3690225299ab5291b382`. A later lint-only type alias changes the build hash. Qualify the exact EIF used for deployment.

## Earlier upgrade rehearsal

On 2026-11-21, two disposable EC2 Nitro hosts in `eu-north-1` served two measured releases of the native devnet build at the same time. Each used separately sealed wrapping keys. The enclave rejected an incomplete, repeated or swapped pair of shares. KMS rejected a request without attestation, a key-policy rewrite and an attempt by the replacement to unwrap the old image's share. Using the SPR SDK, the authorized wallet recovered the same committed note before promotion, while both versions were serving, and after terminating the old enclave. Both boot connection keys changed while the owner's note public keys stayed the same. A new SDK instance rejected the previously signed policy using the same checkpoint. The release CLI also added two genuine AWS KMS signatures that the SDK verified.

The rehearsed devnet executable SHA-256 was `7f00aed5a6ce1f6bc60ab95d848ff5195e9a8133cc16e459a3a0401918b3e10b`. A subsequent lint cleanup replaced the zero-commitment check with the equivalent slice membership check. The review and deployment must use the measurements for the artifact they actually build.

That prototype used the 2-of-2 layout, SSM loopback forwarding, a shared lab AWS account and a synthetic note. The committed evidence fixture captures a genuine AWS-signed document from the rehearsal. It contains only public evidence and the verifier inputs. Both test instances and their IAM and S3 resources were removed. KMS confirmed all ten disposable keys were pending deletion.

## Reproduce and collect

- Run `just ci` on Linux, `python3 -B -m unittest discover -s tests/nitro`, and the [native build and runtime flow](../enclave/deploy/nitro/README.md). Linux runs the OpenSSL bootstrap and transport tests. The rehearsal also ran the native Linux library tests on EC2. The Mac workspace suite skips the Linux-specific tests.
- Run `cargo audit --file enclave/native/Cargo.lock` and inspect the production graph with `cargo tree --locked --manifest-path enclave/native/Cargo.toml --target x86_64-unknown-linux-musl -e normal`. The native lock reported zero vulnerabilities and an unmaintained `serde_cbor` dependency used by the AWS NSM driver. The hosted workspace lock still reports its own QuorumOS dependency advisories.
- `pnpm audit --prod` reported a low-severity `elliptic` advisory through the example's SPR peer and Phala DCAP dependency. Native request encryption and release verification use Noble, the native verifier uses WebCrypto, and this audit did not exercise the Phala prover path. [GHSA-848j-6mx2-7j84](https://github.com/advisories/GHSA-848j-6mx2-7j84)
- Follow [the invariants](INVARIANTS.md). Archive the audited commit, EIF and executable hashes, PCRs, actual installed AWS policies, signed policy and fingerprints, CloudTrail records, authenticated ingress canary outputs and custody/recovery evidence. Handle share backups and live credentials outside the audit artifacts.
