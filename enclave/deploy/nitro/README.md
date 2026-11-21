# Deploy and rotate native Nitro

A wallet attests one HTTPS slot before encrypting to its boot key. Route each
slot to one enclave. A release policy can authorize several slots or custody
epochs during an upgrade. Each slot uses its own measured EIF and six sealed
wrapping keys in independently administered accounts.

## Set up custody

Use six independently administered AWS accounts, a separate enclave host
account and a dedicated publisher role for the custody bucket. Each custodian
uses distinct IAM roles for opening its share and retiring its keys. In each
custody account provision an RSA KMS `ENCRYPT_DECRYPT` key and a P-256 KMS
`SIGN_VERIFY` key. Only the custodian role should sign acknowledgements. The
three approval keys are P-256 KMS keys in three separately administered
accounts. The commands need `kms:Verify` on the public signing keys they check.
They only need `kms:Sign` when approving or acknowledging a record.

Pin `trust.json` outside the host and artifact distributor. It contains
`network`, `securityDomainId` (32 random bytes in lowercase hex), `approvalKeys`
(three immutable KMS signing key ARNs), and `ledger` with `bucket`, `region` and
`account` (the 12-digit bucket owner's account ID). The ordered `roster.json`
contains six entries with `recoveryKeyArn`, `acknowledgementKeyArn`,
`custodianRole` and `retirementRole`. The first entry owns share 1.

```sh
nitro=enclave/deploy/nitro
python3 "$nitro/custody_ledger.py" trust.json policy "$publisher_role" "$reader_role" > ledger-policy.json
python3 "$nitro/custody_ledger.py" trust.json recovery-policy "$custodian_role" "$retirement_role" > recovery-policy.json
python3 "$nitro/custody_ledger.py" trust.json acknowledgement-policy "$custodian_role" "$retirement_role" > ack-policy.json
```

Supply every ledger reader role to `policy`. Install it on a private,
versioned bucket without expiration, replication or alternate writers. Restrict
bucket administration independently of the enclave host and publisher. The
policy requires conditional creation and denies object deletion. The publisher
can make progress unavailable, for example by failing to publish. Readers
verify two pinned approvals and six custodian acknowledgements even when
reading directly from S3. Install each custodian's two policies at key creation
with `--bypass-policy-lockout-safety-check`. Only the custodian role can decrypt
with the recovery key or sign with the acknowledgement key. Governance reviewers can retrieve the recovery public key to verify its
fingerprint. Grant the corresponding cross-account IAM permissions explicitly.

## Commit a custody epoch

1. Create `configuration.json` with `releaseId`, `securityDomainId` and
   `deployment`. Initialization uses `{"mode":"initialize","recipientPublicKeys":[...]}`.
   Each recipient is the lowercase-hex DER SPKI of its RSA recovery key, in roster order.
   Build the reviewed executable and package it with the configuration:

   ```sh
   SPR_NETWORK=devnet RUSTFLAGS='-C target-feature=+crt-static' \
     cargo build --locked --release --manifest-path enclave/native/Cargo.toml \
     --target x86_64-unknown-linux-musl
   "$nitro/build-eif.sh" \
     enclave/native/target/x86_64-unknown-linux-musl/release/spr-nitro-decryption-service \
     configuration.json "$build_dir"
   nitro-cli run-enclave --enclave-name spr-decrypt --eif-path "$build_dir/enclave.eif" \
     --enclave-cid 16 --cpu-count 2 --memory 512
   ```

2. Forward the ceremony's vsock port 44031 through SSM to loopback. Use `pcrs.json`
   with keys `0` through `3`, derived from the independently reviewed EIF and
   exact host role. Capture the fresh Nitro proof and the encrypted packages:

   ```sh
   pnpm --dir example exec tsx ../xtask/nitro-ceremony.ts \
     http://127.0.0.1:55443/ "$build_dir/configuration.json" pcrs.json devnet custody-capture.json
   python3 "$nitro/custody_ledger.py" trust.json draft custody-capture.json "$build_dir" \
     "$host_role" roster.json > epoch-draft.json
   ```

3. Two approval signers each run `sign` with the measured build. The command
   rechecks the archived AWS evidence and the six KMS public keys. Pass each
   updated document to the next signer. Each custodian then acknowledges in its
   own account, after decrypting and checking its committed share. Publish the
   fully acknowledged document with the dedicated publisher role.

   ```sh
   python3 "$nitro/custody_ledger.py" trust.json sign epoch-draft.json "$build_dir" "$approval_key" epoch-signed.json
   python3 "$nitro/custody_ledger.py" trust.json acknowledge epoch-signed.json "$share_index" epoch-ack.json
   python3 "$nitro/custody_ledger.py" trust.json publish epoch-ack.json
   python3 "$nitro/custody_ledger.py" trust.json read 1 > receipt.json
   ```

   `publish` requires two approvals and all six acknowledgements on the same
   candidate. The first successful conditional write fixes the receipt for that
   epoch. Each rotation must name the previous committed receipt and preserve
   its seed commitment. The encrypted packages and attestation stay in the
   ledger. Custodians can retain separate copies for disaster recovery.

## Commission a measured target

1. For serving, copy the canonical receipt's `custody` object into
   `{"mode":"serve","custody":{...}}`. Build and review the EIF. In the six
   custody accounts, install the final wrapping policy at key creation using
   `kms_policy.py` with the build measurements and exact host, custodian and
   retirement roles. Keep the returned immutable ARNs in `wrapping-keys.json`,
   an array in roster order. Choose an approval deadline in Unix seconds.
2. Two approval signers independently check and sign the target manifest. It
   binds the canonical receipt, mode, EIF, configuration, measurements and
   six wrapping keys. A rotation draft also takes `--next-roster roster-next.json`.

   ```sh
   python3 "$nitro/deployment.py" trust.json "$build_dir" draft "$host_role" wrapping-keys.json \
     "$approval_deadline" > target-draft.json
   python3 "$nitro/deployment.py" trust.json "$build_dir" sign target-draft.json "$approval_key" target-signed.json
   python3 "$nitro/wrap_share.py" trust.json target-signed.json "$build_dir" "$share_index" share.kms
   ```

   `wrap_share.py` reads the authenticated receipt from the ledger and checks
   the actual installed wrapping and recovery key policies before decrypting
   the share. A trusted custodian workstation sees one plaintext share during
   acknowledgement and wrapping. The tool writes only the wrapped ciphertext.
   Obtain more than three ciphertexts so a boot can tolerate unavailable keys.
3. Give the parent `kms:Decrypt` only on the exact slot's wrapping key ARNs,
   and read access to pinned versions of the EIF and wrapped artifacts. Its
   plan contains `epoch` and six ordered `keys` entries with `keyArn` and a
   relative `ciphertext` path. An unavailable slot may omit its ciphertext file.

   ```sh
   python3 "$nitro/provision.py" 16 "$network" "$security_domain" "$release_id" "$key_plan"
   ```

4. Keep port 44031 private. Forward port 44030 through TLS without caching.
   Bound request sizes and ingress concurrency, keep each HTTPS slot tied to
   one boot at a time, and qualify it with wallet attestation and an
   owner-signed canary.

## Rotate custody and activate releases

1. Use `{"mode":"rotate","previous":{...},"recipientPublicKeys":[...]}` as
   `deployment`. Copy the exact previous custody record. Supply six public
   fresh RSA recovery keys for the next epoch, including any replacements.
   Build a distinct rotation EIF. Three old custodians wrap their previous
   shares to that EIF, using its release ID and the old custody epoch. The
   rotation enclave verifies the old seed commitment before issuing the new
   shares. Commit the new receipt only after all six new keys acknowledge it.
2. Commission new serving slots from the new receipt and cold-boot from three
   new shares. Through the real ingress, use the wallet to open a note
   addressed before rotation. Keep healthy old slots during qualification.
3. Sign and publish a higher-sequence policy covering the qualified slots.
   Allow overlap while the floor covers both epochs. To retire an epoch,
   publish another higher sequence, set `minimumCustodyEpoch` to the new epoch
   and remove all old targets. Drain the older sessions, stop the old enclaves
   and retire their wrapping and recovery keys after qualification.
   A higher policy sequence cannot lower the recorded floor. Rebuilding an
   older serving version for the current epoch can qualify it again.
4. A leaked threshold of old shares still exposes the underlying seed.
   Refreshing shares controls future access. A seed compromise requires
   owner-authorized migration to a new seed domain.

The canonical policy starts with `{"policy":...,"signatures":[]}`. Its policy
fields are `version`, `action`, `network`, `securityDomainId`, `noteSeedCommitment`,
`minimumCustodyEpoch`, `sequence`, `validFromMs`, `expiresAtMs` and `targets`.
Each target contains `endpoint`, `releaseId`, `executableSha256`,
`custodyEpoch` and `pcrs`. Pin network, domain, seed commitment, minimum sequence,
minimum custody epoch, signer keys and threshold out-of-band. Times, sequence
and epochs are canonical decimal strings. The wallet stores the sequence,
policy digest and custody floor atomically. `activate` requires a verified
replica before the wallet advances the checkpoint. An emergency `revoke`
requires an empty target list and advances the checkpoint as soon as the wallet
verifies the policy signatures. Publish policy changes through a
single conditional writer and alert before expiration.

```sh
cargo xtask nitro-sign policy.json --key "$signing_key_arn" --public-key "$signer_sec1_hex"
```

Wrap-key replacements for a new EIF use the existing receipt and new sealed key
ARNs. Custodian replacements use a measured rotation. Wallet release signing
keys rotate through the wallet's independently distributed trust configuration.

[Security model](../../NITRO.md) · [Test invariants](../../../tests/INVARIANTS.md) · [Audit handoff](../../../tests/AUDIT.md)
