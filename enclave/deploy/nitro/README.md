# Deploy and upgrade native Nitro

Deploy the native service alongside the existing prover infrastructure. Use one HTTPS route per replica slot and forward each slot to exactly one running enclave. Wallets select and attest a slot before encrypting to its boot key. The release policy can authorize multiple slots across versions and regions. Each slot has a separately measured release and two immutable KMS key ARNs.

## One-time setup

- Assign two note-share custodians with separate AWS accounts and independent offline backups. Each custodian generates and retains one uniformly random 32-byte share, and publishes only its SHA-256. Preserve share order for the lifetime of the wallet domain. The two shares meet for the first time inside the measured enclave.
- Choose a random security domain per network. Pin it, the ordered public commitment from both hashes, the policy HTTPS URL, the initial minimum sequence and at least two independently controlled release authority keys in the wallet integration. Use two of three KMS `ECC_NIST_P256` signing keys without giving the deploy role their signing permissions.
- Configure the wallet's checkpoint store to atomically record the greatest sequence and its exact digest for this network and domain. Returning false on storage failure prevents use of an unrecorded policy. Back up the checkpoint with wallet state. Raise the application's minimum sequence when revoking a release for clients with empty state.
- Use independently administered IAM roles for each share custodian, each share key's retirement and the EC2 parent. Limit the EC2 role's identity policy to `kms:Decrypt` on the two exact key ARNs for that slot and immutable version reads of its EIF and wrapped shares. The production relay refuses two share keys in the same AWS account.

## Prepare a target

1. On the reviewed commit and pinned build environment, build the production artifact with its native lockfile. Record the source revision, executable digest, Rust toolchain and build environment. Use a trusted instance with a pinned Nitro CLI to build the EIF. This example builds devnet.

   ```sh
   SPR_NETWORK=devnet RUSTFLAGS='-C target-feature=+crt-static' \
     cargo build --locked --release --manifest-path enclave/native/Cargo.toml \
     --target x86_64-unknown-linux-musl
   enclave/deploy/nitro/build-eif.sh \
     enclave/native/target/x86_64-unknown-linux-musl/release/spr-nitro-decryption-service \
     "$release_id" "$security_domain" "$share_1_sha256" "$share_2_sha256" "$build_dir"
   ```

2. Have each custodian verify the source, measurement record, launch arguments, EIF and parent role. Render that custodian's KMS policy with `kms_policy.py "$build_dir/measurements.json"`, providing `--host-role`, `--custodian-role`, `--key-admin-role`, `--network`, `--security-domain`, `--release` and `--share 1` or `2`. PCR3 is derived from the exact role ARN. Create each key with the final resource policy installed at creation. AWS requires `--bypass-policy-lockout-safety-check` for this sealed policy. Re-read and compare the installed policy before wrapping the share. Every deployment gets new keys. A sealed key cannot be widened for another EIF or a newly created role.
3. Each custodian uses its `Encrypt` permission to wrap its own share under its exact key ARN and context. The context is the same one the policy generator emitted. Upload only the returned `CiphertextBlob` in binary form to a private immutable object specific to this release and share. Use version-pinned objects, verify their hashes and the EIF checksum before launch, and retain the encrypted objects and build artifacts for the rollback window.
4. Boot the verified EIF in normal mode, then run the provisioning helper on the parent. If provisioning times out, terminate the failed enclave before retrying the same verified artifacts.

   ```sh
   nitro-cli run-enclave --enclave-name spr-decrypt --eif-path "$build_dir/enclave.eif" \
     --enclave-cid 16 --cpu-count 2 --memory 512
   python3 enclave/deploy/nitro/provision.py 16 "$network" "$security_domain" "$release_id" \
     "$key_1_arn" "$wrapped_share_1" "$key_2_arn" "$wrapped_share_2"
   ```

5. Set up ingress for `/v1/nitro/attestation` and `/v1/operations` through port 44030. Keep provisioning port 44031 off ingress. Apply TLS, request and connection limits, deadlines, and no response caching. Check `/health` internally. Confirm that the wallet can attest the target through its real ingress and verify a public-key lookup and owner-signed note decryption. Health alone does not qualify a target.

## Promote, roll back and retire

The policy file is `{"policy":...,"signatures":[]}` before signing. The policy contains `version` (number 1), `network`, `securityDomainId`, `noteSeedCommitment`, `sequence`, `validFromMs`, `expiresAtMs` and `targets`. Times are decimal strings in milliseconds. Sequence is a positive decimal string. Each target contains `endpoint` (canonical absolute HTTPS URL), `releaseId`, `executableSha256` and `pcrs` with keys `0` through `3`. Hashes are lowercase hex. Commit and review canonical JSON before approving it. For this ASCII schema `jq -cS` followed by removal of its final newline produces the required bytes.

Each release signer appends one verified signature to the same file in sequence. The signing tool requires the signer's independently pinned SEC1 public key and the immutable KMS key ARN.

```sh
cargo xtask nitro-sign policy.json --key "$signing_key_arn" --public-key "$signer_sec1_hex"
```

Use a new, higher sequence for each publish. Set a validity window of at most seven days and alert before expiry. Keep the previous policy and its review evidence in immutable storage. Publish with a single deployment writer using a conditional replacement against the version it reviewed. A valid policy makes every listed slot eligible for real wallet traffic.

1. Put the new slot online and verify it through its private qualification ingress with the real SDK. In devnet, open and sweep a note addressed before the upgrade. Keep the old slots serving during qualification.
2. Publish the higher-sequence policy with the verified old and new slots. Observe real attestation and operation checks for each slot. Allow at least the 60-second SDK session window before assuming an already connected client can switch.
3. Publish another higher-sequence policy removing old slots. Drain and stop those hosts after the session window. Keep the old sealed keys and wrapped shares only for the approved rollback window. An operational rollback publishes a higher sequence that reauthorizes a previously qualified slot.
4. On suspected compromise, remove affected routes in a higher-sequence policy, stop affected enclaves, and have both custodians' retirement roles schedule their keys for deletion to prevent new unwraps. Raise the wallet's minimum sequence through its trusted distribution channel. Treat already exported note seeds as compromised and migrate value to a new domain. Revoking a release cannot recall an exported seed or immediately invalidate every previously signed policy.

Deploy independent replica slots before mainnet. Exercise loss of one slot, custody account or region. Run the certificate-lifetime drill and enforce replacement before clients reject a long-running boot's certificate. Retain CloudTrail evidence of every attested unwrap, policy publication, role action and KMS signing event. Never log request plaintext, shares, response keys, or owner signatures. Keep the release, custody, and recovery responsibilities separate.

See [the threat model](../../NITRO.md), [invariants](../../../tests/INVARIANTS.md), and [audit handoff](../../../tests/AUDIT.md).
