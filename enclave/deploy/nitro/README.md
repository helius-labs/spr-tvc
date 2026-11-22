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
python3 "$nitro/custody_ledger.py" trust.json policy "$ledger_admin_role" "$publisher_role" "$reader_role" > ledger-policy.json
python3 "$nitro/custody_ledger.py" trust.json reader-policy > ledger-reader-policy.json
python3 "$nitro/custody_ledger.py" trust.json recovery-policy "$custodian_role" "$retirement_role" 1 > recovery-policy.json
python3 "$nitro/custody_ledger.py" trust.json acknowledgement-policy "$custodian_role" "$retirement_role" > ack-policy.json
```

Supply every ledger reader role to `policy`, and attach the generated read
policy to each cross-account reader role in its own account. Install the bucket
policy on a private versioned bucket with bucket-owner-enforced ownership,
public access blocked, and lifecycle expiration and replication off. The bucket
policy restricts administration to a separate role and permits the publisher
to create objects conditionally. Protect account root and keep the publisher
and host unable to assume the administrator role. Readers verify two pinned
approvals and six custodian acknowledgements even when reading directly from
S3. If a canonical record fails verification, halt the affected operation and
compare the record with the current trust schedule and signed archives. The
independent bucket administrator investigates and preserves the versions and
audit logs before any repair. A valid retirement record permanently closes its
epoch. Install each custodian's two policies at key creation
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
   independently of the build. Dispatch mainnet builds from protected `main`.
   A different GitHub user reviews the artifact linked in the run summary and
   approves `image-publish`. Dispatch a new run if the build needs another attempt.
   Download the run's `native-eif-<network>-<commit>` artifact. Keep the application, configuration,
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
   epoch. A rotated receipt pins the previous receipt and the registered
   rotation approval. Drafting and signing check the measured configuration.
   Acknowledgement, publication and online reads verify the same image, host
   role and successor roster. The seed commitment stays stable.

   Use `archive <epoch>` to retain the encrypted packages, evidence and
   signatures. Pin the SHA-256 over canonical JSON without a trailing newline.
   `verify-archive` checks the independent pin and signatures without AWS.
   Retain the original registered approval with each rotated receipt's audit
   evidence.

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
   python3 "$nitro/deployment.py" trust.json "$build_dir" host-policy target-signed.json > host-kms-policy.json
   python3 "$nitro/wrap_share.py" trust.json target-signed.json "$build_dir" "$share_index" "$share_index.kms"
   ```

   Register with the dedicated ledger publisher. The ledger keeps the exact
   signed target and all six wrapping-key ARNs. Within an epoch, a release ID
   and PCR0–PCR3 identify one wrapping-key set. Use a fresh release identity
   for a different key set. A fresh approval can renew the wrapping deadline
   without replacing the registered target. Before decrypting a share,
   `wrap_share.py` checks registration, the open epoch, and both installed key
   policies. A trusted custodian workstation sees one plaintext share during
   acknowledgement and wrapping. The tool writes only the wrapped ciphertext.
   Obtain more than three ciphertexts so a boot can tolerate unavailable keys.
3. Use a host role dedicated to the measured target. Install
   `host-kms-policy.json` as an inline IAM policy on that role. Cross-account
   KMS requires it in addition to the policies on the keys.
   Archive the host policy with the approved target. Give the parent read
   access to pinned versions of the EIF, signed target and wrapped shares.
   Record the SHA-256 of `target-signed.json` in the reviewed host deployment
   configuration. Copy it verbatim and place each wrapped share at
   `shares/<slot>.kms` next to it. Omit the file for an unavailable slot.
   The approval deadline gates new share wraps. Cold boots can use existing
   wrapped shares from the pinned target until the keys are retired.

   ```sh
   python3 "$nitro/provision.py" 16 "$approved_target" --target-sha256 "$target_sha256"
   ```

4. Keep port 44031 private. Forward port 44030 through TLS without caching.
   Open one HTTP/1 request per upstream vsock connection. The enclave closes
   the connection after its response and caps concurrent serving connections
   at 64. Headers have a 16 KiB limit and three-second read deadline.
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
2. Commission new serving slots from the new receipt. On a fresh enclave run,
   pass `--slots 2 4 6` to `provision.py` to use only those three current slots.
   Provisioning fails if any selected slot fails. Capture the accepted slot
   list. Through the real ingress, use the wallet to open a note
   addressed before rotation. Keep healthy old slots during qualification.
3. Allow overlap while the wallet policy floor covers both epochs. After a
   cold boot and wallet canary on the new epoch, publish a policy with
   `minimumCustodyEpoch` at the new epoch. Drain old sessions and stop the old
   enclaves. An older executable can be built for the current epoch if needed.
4. Pin the file SHA-256 of the independently distributed wallet trust bundle
   as `walletTrustSha256` in the custody trust file. Three current custodians
   run `prove-recovery` in their respective roles. Each command reopens that
   custodian's package from the replacement receipt and signs the retirement
   candidate with its acknowledgement key. Keep those keys enabled for the
   current epoch. Pass each output to the next custodian.

   Two custody approval signers then sign, and the ledger publisher commits
   the record within 24 hours of drafting. Signers and the publisher need
   `kms:DescribeKey` on the proven recovery keys and check that at least
   three are enabled. Draft, sign and publish check that both public buckets
   agree before and after attestation and that a live replacement matches
   the registered serving target. After a timeout, retry the same signed
   document. The tool verifies a committed record against its historical
   roster and S3 timestamp, even after the recovery window closes. If the
   write never committed and the window or policy changed, draft a new
   candidate. A committed record closes the old epoch to new wraps. Its key
   inventory includes wrapping keys registered before the commit, including
   those for requests in flight.

   ```sh
   python3 "$nitro/retirement.py" trust.json draft wallet-trust.json 1 2 > retire-draft.json
   python3 "$nitro/retirement.py" trust.json prove-recovery retire-draft.json 2 > retire-proof-1.json
   python3 "$nitro/retirement.py" trust.json prove-recovery retire-proof-1.json 4 > retire-proof-2.json
   python3 "$nitro/retirement.py" trust.json prove-recovery retire-proof-2.json 6 > retire-proof-3.json
   python3 "$nitro/retirement.py" trust.json sign wallet-trust.json retire-proof-3.json "$first_approval_key" > retire-signed-1.json
   python3 "$nitro/retirement.py" trust.json sign wallet-trust.json retire-signed-1.json "$second_approval_key" > retire-signed-2.json
   python3 "$nitro/retirement.py" trust.json publish wallet-trust.json retire-signed-2.json
   python3 "$nitro/retirement.py" trust.json inspect 1 "$share_index"
   ```

   Before scheduling any deletion, cold-boot with exactly three current slots
   and open a note from before rotation. Each retirement role verifies its
   inventory, schedules approved keys, and repeats `inspect --check-inactive`.
   Scheduling immediately disables cryptographic use. Canceling leaves the
   key disabled, and the sealed policy grants no permission to re-enable it.
   Capture the results before AWS deletes the metadata. Repeat the cold boot
   and canary after retirement. Retain the old signed receipt and public
   trust pins. [AWS key deletion](https://docs.aws.amazon.com/kms/latest/APIReference/API_ScheduleKeyDeletion.html) · [AWS cancellation behavior](https://docs.aws.amazon.com/kms/latest/APIReference/API_CancelKeyDeletion.html)
5. A leaked threshold of old shares still exposes the underlying seed.
   Refreshing shares controls future access. A seed compromise requires
   owner-authorized migration to a new seed domain.

## Publish wallet policy

Use two versioned S3 publication buckets in independently administered AWS
accounts, separate from the private custody ledger. Give each bucket a publisher
role and a separate administrator role in its own account. Keep all role
assumption paths independent across the two accounts and separate from the host
and ingress. The bucket policy bars publishers from changing its controls.
Allow public reads of exactly the policy object. Disable lifecycle
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
Register each serving target before signing an activation. The signing and
publication tools match its executable, release ID and PCR0–PCR3 to the
registered serving image and verify its committed, active custody epoch.
Give release signers and both publishers scoped ledger read access using
`reader-policy` and distribute the custody trust file independently. A revoke
policy needs only the wallet signing and publication flow. Pin network, domain, seed
commitment, minimum sequence, minimum custody epoch, signer keys, threshold and
`publications` with two `{bucket, region, account}` entries in `wallet-trust.json`.
List the primary first and the mirror second.
Times, sequence
and epochs are canonical decimal strings. The wallet stores the sequence,
policy digest and custody floor atomically. `activate` requires a verified
replica before the wallet advances the checkpoint. An emergency `revoke`
requires an empty target list and advances the checkpoint as soon as the wallet
verifies both signed heads. Each publisher checks the predecessor, verifies
that every activation target attests, and writes against its observed ETag.
Publish from the first listed bucket's AWS account, then mirror the exact signed
file from the second account. The tool checks the full signed file at both
buckets before advancing past it. Use a new revision to change its signatures.
Wallets use the primary's signed policy when the mirror serves the same
policy or its exact predecessor. A mirror ahead of the primary blocks new
connections. Retirement requires agreement. Set alerts for mismatched heads
and approaching expiration.

```sh
cargo xtask nitro-sign policy.json --key "$signing_key_arn" --public-key "$signer_sec1_hex" --custody-trust "$custody_trust"
pnpm --dir example exec tsx ../xtask/nitro-publish.ts "$wallet_trust" "$bucket" --bucket-policy "$bucket_admin_role" "$publisher_role"
pnpm --dir example exec tsx ../xtask/nitro-publish.ts "$wallet_trust" "$bucket" "$signed_policy" --custody-trust "$custody_trust"
```

Wrap-key replacements for a new EIF use the existing receipt and new sealed key
ARNs. Custodian replacements use a measured rotation.

### Rotate wallet signing keys

1. Have the outgoing and incoming quorums sign the same next revision. Keep
   the domain, bucket pins and custody floor. The file can carry up to eight
   distinct signatures.
2. Publish that signed file to both buckets using the outgoing trust. Confirm
   both copies verify under the incoming trust before distributing the new pins.
   Pin the transition revision as the minimum sequence in the new trust bundle.
3. After wallets adopt the new trust, publish the next revision with the incoming
   quorum and retire the outgoing keys.

If the outgoing quorum is unavailable or compromised, distribute new wallet
trust independently and publish a successor signed by the incoming quorum. Use
`--previous-trust` to verify the published predecessor. Wallets need the new
pins and both updated bucket heads to resume using the service.

[Security model](../../NITRO.md) · [Test invariants](../../../tests/INVARIANTS.md) · [Audit handoff](../../../tests/AUDIT.md)
