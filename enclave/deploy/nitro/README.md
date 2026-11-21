# Deploy and rotate native Nitro

A wallet attests one HTTPS slot before encrypting to its boot key. Route each
slot to one enclave. A release policy can authorize several slots or custody
epochs during an upgrade. Each slot uses its own measured EIF and six sealed
wrapping keys in independently administered accounts.

## Create a custody record

1. Assign six custodians. Each retains an independently controlled RSA KMS key
   with `ENCRYPT_DECRYPT` usage and recovery access. Choose a random security
   domain per network. Keep its seed commitment stable in the wallet trust
   configuration. Use separate KMS P-256 keys for the release signing quorum.
2. Prepare a measured configuration with `releaseId`, `securityDomainId`
   (32 bytes of lowercase hex) and `deployment`. For initialization, set
   `deployment` to `{"mode":"initialize","recipientPublicKeys":[...]}`. Use
   six ordered DER SPKI public keys in lowercase hex from the custodians'
   immutable RSA key ARNs. Record the expected release, network and measurements
   independently of the parent.
3. Build the EIF with a reviewed checkout and pinned build environment. Record
   the source revision, toolchain, build environment and resulting hashes.
   Start it in normal mode.

   ```sh
   SPR_NETWORK=devnet RUSTFLAGS='-C target-feature=+crt-static' \
     cargo build --locked --release --manifest-path enclave/native/Cargo.toml \
     --target x86_64-unknown-linux-musl
   enclave/deploy/nitro/build-eif.sh \
     enclave/native/target/x86_64-unknown-linux-musl/release/spr-nitro-decryption-service \
     "$configuration" "$build_dir"
   nitro-cli run-enclave --enclave-name spr-decrypt --eif-path "$build_dir/enclave.eif" \
     --enclave-cid 16 --cpu-count 2 --memory 512
   ```

4. Forward vsock port 44031 to a parent loopback port and open an SSM tunnel.
   Each custodian verifies the receipt on its own trusted machine using a fresh
   challenge and the reviewed configuration and PCRs. The PCR file has keys
   `0` through `3`. Derive PCR3 from the exact parent role ARN.

   ```sh
   pnpm --filter spr-tvc-typescript-client-example exec tsx ../xtask/nitro-ceremony.ts \
     http://127.0.0.1:55443/ "$configuration" "$pcrs" "$network" "$verified_receipt"
   ```

   Commit to one authenticated receipt per epoch. Record its seed commitment
   independently. Retain each custodian's encrypted package separately. A
   reboot can generate a different record. Never combine packages from two
   receipts.

## Commission a measured target

1. For a serving slot, use `{"mode":"serve","custody":{...}}` as `deployment`.
   Copy the exact `custody` object from the verified receipt. Build and review
   the EIF. For each share, render the final key policy with
   `kms_policy.py "$build_dir/measurements.json"` and the host, custodian and
   retirement roles, network, domain, release, custody epoch and slot. The
   program derives PCR3 from the role ARN. Install the policy at key creation
   with `--bypass-policy-lockout-safety-check` and verify the installed policy
   before wrapping. A sealed key cannot be widened to another role or EIF.
2. In its own account, each participating custodian checks the authenticated
   receipt against its immutable RSA recovery key and wraps its own share for
   the target. The helper verifies the share commitment and writes only the
   new ciphertext. Three custodians must provide usable ciphertexts. Obtain
   more if automatic boot must tolerate unavailable accounts.

   ```sh
   python3 enclave/deploy/nitro/wrap_share.py "$verified_receipt" "$share_index" \
     "$recovery_key_arn" "$wrapping_key_arn" "$release_id" "$wrapped_share"
   ```

3. The parent role gets `kms:Decrypt` only on exact wrapping key ARNs. Give it
   read access to pinned versions of the verified EIF and wrapped artifacts.
   The local plan has `epoch` and six ordered `keys` entries, each with
   `keyArn` and a relative `ciphertext` path. An unavailable slot may have no
   ciphertext file. At least three shares must reach the correct enclave.

   ```sh
   python3 enclave/deploy/nitro/provision.py 16 "$network" "$security_domain" "$release_id" "$key_plan"
   ```

4. Keep port 44031 private. Forward attestation and operations to vsock port
   44030, with no cache, bounded requests and TLS. Verify the exact slot via
   wallet attestation and an owner-signed canary. HTTP health alone does not
   qualify a slot.

## Rotate custody and activate releases

1. Use `{"mode":"rotate","previous":{...},"recipientPublicKeys":[...]}` as
   `deployment`. Copy the exact previous custody record. Supply six public
   keys for the next epoch, including the new key for each replaced custodian.
   Build a distinct rotation EIF. Three old custodians wrap their previous
   shares to that EIF, using its release ID and the old custody epoch. The
   rotation enclave verifies the old seed commitment before issuing the new
   shares. Verify the new receipt and confirm its seed commitment is unchanged.
2. Commission new serving slots from the new receipt and cold-boot from three
   new shares. Through the real ingress, use the wallet to open a note
   addressed before rotation. Keep healthy old slots during qualification.
3. Sign and publish a higher-sequence policy covering the qualified slots.
   Allow overlap while the floor covers both epochs. To retire an epoch,
   publish another higher sequence, set `minimumCustodyEpoch` to the new epoch
   and remove all old targets. Drain the older sessions, stop the old enclaves
   and retire their wrapping keys and retired recovery keys after qualification.
   A higher policy sequence cannot lower the recorded floor. Rebuilding an
   older serving version for the current epoch can qualify it again.
4. A leaked threshold of old shares still exposes the underlying seed.
   Refreshing shares controls future access. A seed compromise requires
   owner-authorized migration to a new seed domain.

The canonical policy starts with `{"policy":...,"signatures":[]}`. Its policy
fields are `version`, `network`, `securityDomainId`, `noteSeedCommitment`,
`minimumCustodyEpoch`, `sequence`, `validFromMs`, `expiresAtMs` and `targets`.
Each target contains `endpoint`, `releaseId`, `executableSha256`,
`custodyEpoch` and `pcrs`. Pin network, domain, seed commitment, minimum sequence,
minimum custody epoch, signer keys and threshold out-of-band. Times, sequence
and epochs are canonical decimal strings. The wallet stores the sequence,
policy digest and custody floor atomically. Publish policy changes through a
single conditional writer and alert before expiration.

```sh
cargo xtask nitro-sign policy.json --key "$signing_key_arn" --public-key "$signer_sec1_hex"
```

Wrap-key replacements for a new EIF use the existing receipt and new sealed key
ARNs. Custodian replacements use a measured rotation. Wallet release signing
keys rotate through the wallet's independently distributed trust configuration.

[Security model](../../NITRO.md) · [Test invariants](../../../tests/INVARIANTS.md) · [Audit handoff](../../../tests/AUDIT.md)
