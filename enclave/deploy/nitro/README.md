# Deploy and rotate native Nitro

A wallet attests one HTTPS slot before encrypting to its boot key. Route each
slot to one enclave. A release policy can authorize several slots or custody
epochs during an upgrade. Each slot uses its own measured EIF and six sealed
wrapping keys in independently administered accounts.

## Set up custody

Use six independently administered AWS accounts, a separate enclave host
account and a dedicated publisher role for the custody bucket. Each custodian
uses distinct IAM roles for opening its share and retiring its keys. In each
custody account provision a single-region, KMS-generated RSA `ENCRYPT_DECRYPT`
key and a P-256 `SIGN_VERIFY` key. Only the custodian role signs acknowledgements.
The three approval keys are P-256 KMS keys in three separately administered
accounts. Sign with KMS and verify the signatures locally with OpenSSL.
Export public keys as `{keyArn, publicKey}` with `python3 enclave/deploy/nitro/approval.py "$key_arn"`.

Pin `trust.json` outside the host and artifact distributor. It contains
`network`, `securityDomainId` (32 random bytes in lowercase hex), `approvalKeys`
and `ledger` with `bucket`, `region` and `account` (the 12-digit bucket owner's
account ID). `approvalKeys` is an increasing array of `{fromEpoch, keys}`.
Start with `fromEpoch: "1"` and three exported approval key objects. The ordered
`roster.json` contains six entries with `recoveryKeyArn`, `acknowledgementKey`
(an exported key object), `custodianRole` and `retirementRole`. The first entry
owns share 1.

```sh
nitro=enclave/deploy/nitro
python3 "$nitro/custody_ledger.py" trust.json policy "$publisher_role" "$reader_role" > ledger-policy.json
python3 "$nitro/custody_ledger.py" trust.json recovery-policy "$custodian_role" "$retirement_role" 1 > recovery-policy.json
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
with the recovery key or sign with the acknowledgement key. The recovery
policy is sealed under its assigned epoch. Operators use six fresh recovery
keys for the next epoch. Governance reviewers need `kms:DescribeKey` and
`kms:GetPublicKey` for the proposed recovery and acknowledgement keys.

## Commit a custody epoch

1. Create `configuration.json` with `releaseId`, `securityDomainId` and
   `deployment`. Initialization uses `{"mode":"initialize","recipientPublicKeys":[...]}`.
   Each recipient is the lowercase-hex DER SPKI of its RSA recovery key, in roster order.
   Dispatch `publish-enclave-image.yml` with the public configuration. For
   devnet, use the reviewed branch and record its full Git ref and commit SHA
   independently of the build. Mainnet builds require protected `main` and use
   the `image-publish` environment's required reviewers. Download the run's
   `native-eif-<network>-<commit>` artifact. Keep the application, configuration,
   EIF, measurements and attestation bundle together. Start the measured EIF in
   normal mode.

   ```sh
   source_ref="refs/heads/$reviewed_branch"
   gh workflow run publish-enclave-image.yml --ref "$reviewed_branch" -f network=devnet \
     -F native_configuration=@configuration.json
   gh run download "$build_run" --name "native-eif-devnet-$reviewed_commit" --dir "$build_dir"
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

3. Two approval signers each run `sign` with the measured build, Git ref and
   full commit SHA from review. The command verifies the GitHub build
   attestation, archived AWS evidence and six KMS public keys. Pass each
   updated document to the next signer. Each custodian then acknowledges in its
   own account, after decrypting and checking its committed share. Publish the
   fully acknowledged document with the dedicated publisher role.

   ```sh
   python3 "$nitro/custody_ledger.py" trust.json sign epoch-draft.json "$build_dir" "$approval_key" \
     epoch-signed.json --source-commit "$reviewed_commit" --source-ref "$source_ref"
   python3 "$nitro/custody_ledger.py" trust.json acknowledge epoch-signed.json "$share_index" epoch-ack.json
   python3 "$nitro/custody_ledger.py" trust.json publish epoch-ack.json
   python3 "$nitro/custody_ledger.py" trust.json read 1 > receipt.json
   ```

   `publish` requires two approvals and all six acknowledgements on the same
   candidate. The first successful conditional write fixes the receipt for that
   epoch. Each rotation must name the previous committed receipt and preserve
   its seed commitment. The encrypted packages and attestation stay in the
   ledger. Use `archive <epoch>` to retain the full signed record and pin its
   SHA-256 over canonical JSON without a trailing newline. `verify-archive`
   takes that independent pin and verifies the record without AWS access.

   To change custody approval keys, append a schedule entry for the first
   uncommitted epoch and distribute the updated trust file independently.
   Each receipt uses the roster for its epoch. Target approvals use the
   newest pinned roster. Keep the historical public keys in disaster
   recovery copies of the trust file. The retired private signing keys can
   be disabled once the new roster is ready.

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
   python3 "$nitro/deployment.py" trust.json "$build_dir" sign target-draft.json "$approval_key" \
     target-signed.json --source-commit "$reviewed_commit" --source-ref "$source_ref"
   python3 "$nitro/deployment.py" trust.json "$build_dir" register target-signed.json
   python3 "$nitro/wrap_share.py" trust.json target-signed.json "$build_dir" "$share_index" share.kms
   ```

   Register with the dedicated ledger publisher. The ledger keeps the exact
   signed target and all six wrapping-key ARNs. Before decrypting a share,
   `wrap_share.py` checks registration, the open epoch, and both installed key
   policies. A trusted custodian workstation sees one plaintext share during
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
   Forward browser `OPTIONS` requests for `/v1/nitro/attestation` and
   `/v1/operations`. The enclave supplies the CORS headers for public,
   credential-free `POST` requests. Preserve those headers through ingress.

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
3. Allow overlap while the wallet policy floor covers both epochs. After a
   cold boot and wallet canary on the new epoch, publish a policy with
   `minimumCustodyEpoch` at the new epoch. Drain old sessions and stop the old
   enclaves. An older executable can be built for the current epoch if needed.
4. Pin the file SHA-256 of the independently distributed wallet trust bundle
   as `walletTrustSha256` in the custody trust file. Draft, sign twice and
   publish a retirement record. Each step verifies the canonical wallet policy
   and attests its replacement replicas against the exact committed custody
   record. Both public buckets must agree before and after attestation.
   Publication closes the old epoch to
   new wraps. Each slot's inventory includes its recovery key and all wrapping
   keys registered before retirement, including those from in-flight requests.

   ```sh
   python3 "$nitro/retirement.py" trust.json draft wallet-trust.json 1 2 > retire-draft.json
   python3 "$nitro/retirement.py" trust.json sign wallet-trust.json retire-draft.json "$approval_key" > retire-signed.json
   python3 "$nitro/retirement.py" trust.json publish wallet-trust.json retire-signed.json
   python3 "$nitro/retirement.py" trust.json inspect 1 "$share_index"
   ```

   Each retirement role checks its inventory against the installed KMS policies,
   schedules approved keys for deletion, and repeats `inspect` with
   `--check-inactive`. Capture the results before AWS deletes the key metadata.
   Cold-boot again from three current custodians and open a note from before
   rotation. Retain the old signed receipt and its public trust pins.
5. A leaked threshold of old shares still exposes the underlying seed.
   Refreshing shares controls future access. A seed compromise requires
   owner-authorized migration to a new seed domain.

## Publish wallet policy

Use two versioned S3 publication buckets in independently administered AWS
accounts, separate from the private custody ledger. Give each bucket a publisher
role in its own account. Keep the publisher role, bucket administration and role
assumption paths independent across the two accounts and separate from the host
and ingress. Allow public reads of exactly the policy object. Disable lifecycle
deletion and configure CORS for wallet origins to `GET` with
`x-amz-expected-bucket-owner`. The wallet reads both buckets directly.
Pass absolute file paths to commands run with `pnpm --dir example`.

The canonical policy starts with `{"policy":...,"signatures":[]}`. Its policy
fields are `version`, `action`, `network`, `securityDomainId`, `noteSeedCommitment`,
`minimumCustodyEpoch`, `sequence`, `previousPolicyDigest`, `validFromMs`, `expiresAtMs` and `targets`.
Sequence 1 has `previousPolicyDigest: null`. Each later sequence signs the
digest of the current published policy. Use the domain-separated policy
digest specified in [the Nitro security spec](../../NITRO.md#proposal-and-publication).
Each target contains `endpoint`, `releaseId`, `executableSha256`,
`custodyEpoch`, `custodyDigest` and `pcrs`. Obtain `custodyDigest` with
`python3 "$nitro/custody_ledger.py" trust.json read "$epoch" --custody-digest`.
All targets for that epoch must use the same digest. Pin network, domain, seed
commitment, minimum sequence, minimum custody epoch, signer keys, threshold and
`publications` with two `{bucket, region, account}` entries in `wallet-trust.json`.
Times, sequence
and epochs are canonical decimal strings. The wallet stores the sequence,
policy digest and custody floor atomically. `activate` requires a verified
replica before the wallet advances the checkpoint. An emergency `revoke`
requires an empty target list and advances the checkpoint as soon as the wallet
verifies both signed heads. Each publisher checks the predecessor, verifies
that every activation target attests, and writes against its observed ETag.
Publish from the first listed bucket's AWS account, then mirror the same file
from the second account. The tool requires the first bucket's signed revision
before mirroring and checks the second bucket before advancing the first again.
Retirement requires both buckets to agree. Set alerts for mismatched heads and
approaching expiration.

```sh
cargo xtask nitro-sign policy.json --key "$signing_key_arn" --public-key "$signer_sec1_hex"
pnpm --dir example exec tsx ../xtask/nitro-publish.ts "$wallet_trust" "$bucket" --bucket-policy "$publisher_role"
pnpm --dir example exec tsx ../xtask/nitro-publish.ts "$wallet_trust" "$bucket" "$signed_policy"
```

Wrap-key replacements for a new EIF use the existing receipt and new sealed key
ARNs. Custodian replacements use a measured rotation. For wallet signing-key
rotation, distribute the updated trust bundle independently. Keep a common
signing quorum during rollout so both wallet versions can verify both signed
heads. Use `--previous-trust` when validating a predecessor signed under old
pins. The domain, buckets, sequence and custody floor carry through the transition.

[Security model](../../NITRO.md) · [Test invariants](../../../tests/INVARIANTS.md) · [Audit handoff](../../../tests/AUDIT.md)
