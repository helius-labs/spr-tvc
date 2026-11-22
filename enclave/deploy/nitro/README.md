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
account ID). Each `approvalKeys` entry contains `fromEpoch`, `activeFrom`
in Unix seconds, and three exported key objects. Start at epoch `"1"` with
`activeFrom: 0`. Both values increase with each roster change. The ordered
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
policy on a private, versioned general-purpose bucket with bucket-owner-enforced
ownership, public access blocked, and lifecycle expiration and replication
off. The policy restricts administration to a separate role and allows
conditional single-request uploads. Keep multipart uploads and copies
disallowed so S3's recorded write time can govern custody approvals. Protect
account root and keep the publisher
and host unable to assume the administrator role. Readers verify two pinned
approvals and six custodian acknowledgements even when reading directly from
S3. If a canonical record fails verification, halt the affected operation and
compare the record with the current trust schedule and signed archives. The
independent bucket administrator investigates and preserves the versions and
audit logs before any repair. A valid retirement record permanently closes its
epoch. Custody listings must name the pinned bucket and prefix and account for
every result page. The tools use AWS service endpoints and ignore CLI endpoint
overrides. [AWS CLI endpoint settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html)

Install each custodian's two policies at key creation
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
   uncommitted epoch and set a cutover time. Distribute the updated trust file
   independently before cutover. Custody receipts use the roster for their
   epoch. Target and retirement approvals use the roster active when S3
   committed the record. The tools pause new writes during the final 30
   seconds before cutover. Re-sign unpublished targets and requalify and sign
   unpublished retirements under the new roster after cutover. Preserve the
   historical public keys and original S3 records. [S3 object timestamps](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingMetadata.html) · [Conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html)

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

   Register with the dedicated ledger publisher more than 30 seconds before
   the approval deadline. The ledger verifies that S3 recorded the first
   registration before expiry. It keeps the signed target and all six
   wrapping-key ARNs. Within an epoch, a release ID
   and PCR0–PCR3 identify one wrapping-key set. Use a fresh release identity
   for a different key set. A fresh approval can renew the wrapping deadline
   without replacing the registered target. `wrap_share.py` checks registration
   and both installed key policies. It checks the epoch, roster, and deadline
   immediately before decrypting, before wrapping, and before returning the
   ciphertext. Recovery acknowledgements also require an open epoch. A
   trusted custodian workstation sees one plaintext share during acknowledgement
   and wrapping. The tool writes only the wrapped ciphertext.
   Obtain more than three ciphertexts so a boot can tolerate unavailable keys.
3. Use a host role dedicated to the measured target. Install
   `host-kms-policy.json` as an inline IAM policy on that role. Cross-account
   KMS requires it in addition to the policies on the keys.
   Archive the host policy with the approved target. Give the parent read
   access to pinned versions of the EIF, signed target and wrapped shares.
   Record the SHA-256 of `target-signed.json` in the reviewed host deployment
   configuration. Copy it verbatim and place each wrapped share at
   `shares/<slot>.kms` next to it. Omit the file for an unavailable slot.
   The approval deadline gates first registration and new share wraps. Cold
   boots can use existing wrapped shares from the pinned target until the keys
   are retired.

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
   Provisioning fails if any selected slot fails. Save the three slots that
   the enclave reports using to restore the seed. If the response is lost,
   check the serving attestation or rotation receipt before restarting.
   Through the real ingress, use the wallet to open a note
   addressed before rotation. Keep healthy old slots during qualification.
3. Allow overlap while the wallet policy floor covers both epochs. After a
   cold boot and wallet canary on the new epoch, publish a policy with
   `minimumCustodyEpoch` at the new epoch. Drain old sessions and stop the old
   enclaves. An older executable can be built for the current epoch if needed.
4. Pin the file SHA-256 of the independently distributed wallet trust bundle
   as `walletTrustSha256` in the custody trust file. The retirement draft
   records the replacement's attested boot key ID and actual bootstrap slots.
   The three custodians named by those slots run `prove-recovery` in their
   respective roles. Each command reopens that custodian's package from the
   replacement receipt and signs the candidate with its acknowledgement key. Keep those keys enabled for the
   current epoch. Pass each output to the next custodian.

   Two custody approval signers then sign, and the ledger publisher commits
   the record within 24 hours of drafting. Signers and the publisher need
   `kms:DescribeKey` on the proven recovery keys and check that at least
   three are enabled. Draft, sign and publish check that both public buckets
   agree before and after attestation and that the replacement matches the
   registered serving target. If the attested boot key or slots change, draft
   a new candidate and collect proofs for those slots. After a timeout, retry the same signed
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
   and canary after retirement. The attested slot record proves which shares
   booted the replacement. Record the cold-boot timing, shutdown of the old
   fleet and the on-chain canary separately. Retain the old signed receipt
   and public trust pins. [AWS key deletion](https://docs.aws.amazon.com/kms/latest/APIReference/API_ScheduleKeyDeletion.html) · [AWS cancellation behavior](https://docs.aws.amazon.com/kms/latest/APIReference/API_CancelKeyDeletion.html)

## Attested recovery relay trial

Use fresh devnet keys and a disposable seed domain. Set the relay EIF's
`deployment` to `{"mode":"relay","custodyEpoch":"1","approvalKeys":[...]}`.
Supply the three epoch approval public keys in roster order as uncompressed
SEC1 hex. Add `recoveryRelays` to pinned custody trust, keyed by epoch. Each
entry contains the relay `hostRole` and reviewed `pcrs` from `measurements.json`
(PCR0–PCR2). The tools derive PCR3 from the exact host role.

1. Render the six source policies with `custody_ledger.py relay-recovery-policy`
   after pinning the relay. Pass the custodian role, retirement role and
   custody epoch. Create RSA KMS recovery keys with those policies.
   Give the custody approvers separate read-only inspection profiles in the
   six slot accounts. Each approver runs `custody_ledger.py sign` with
   `--inspection-profiles` in slot order and `--relay-build BUILD COMMIT REF`.
   Use the downloaded relay build, independently reviewed commit SHA and full
   branch ref. The signer verifies GitHub provenance, the pinned PCRs and the
   relay configuration's domain, epoch and ordered approval keys. It checks
   every installed policy and the public key in each measured recovery
   package. KMS `GetKeyPolicy` requires a session in the key's own account.
   Before releasing shares to the rotation EIF, qualify the successor's
   relay and keys using `deployment.py sign --next-relay-build BUILD COMMIT REF`
   and `--next-inspection-profiles`.
2. Forward the measured relay's vsock port 44031 through SSM to a loopback
   port. It serves for ten minutes. Each custodian runs `acknowledge` with
   `--relay-port`. KMS returns a recipient ciphertext. The relay opens it and
   signs fresh evidence that the actual slot and commitment match. The same
   path supplies `retirement.py prove-recovery --relay-port`.
3. Create six fresh RSA target keys using `kms_policy.py` with
   `--wrapping-algorithm RSAES_OAEP_SHA_256`. Draft the target with the same
   algorithm, then sign and register it. Each target key is sealed to the
   measured target and its host role. The signed registry fixes their ARNs in
   slot order. The enclave still verifies every share’s epoch, slot and
   commitment at bootstrap.
4. Draft a release for each participating slot. Two approval signers run
   `sign` independently, each with a read-only profile in that slot account.
   Each command reattests the same relay boot and checks the actual
   destination KMS public key and policy. The signed authorization cannot be
   reused after the relay restarts.

   ```sh
   python3 "$nitro/relay_wrap.py" trust.json target.json "$build_dir" "$slot" --relay-port "$port" \
     draft --inspection-profile "$slot_read_profile" > relay-draft.json
   python3 "$nitro/relay_wrap.py" trust.json target.json "$build_dir" "$slot" --relay-port "$port" \
     sign relay-draft.json "$first_approval_key" --inspection-profile "$slot_read_profile" > relay-signed-1.json
   python3 "$nitro/relay_wrap.py" trust.json target.json "$build_dir" "$slot" --relay-port "$port" \
     sign relay-signed-1.json "$second_approval_key" --inspection-profile "$slot_read_profile" > relay-signed-2.json
   python3 "$nitro/relay_wrap.py" trust.json target.json "$build_dir" "$slot" --relay-port "$port" \
     wrap relay-signed-2.json "shares/$slot.kms"
   ```

   A custodian runs `wrap` in their slot role. The operation supplies only the
   relay's fresh attestation and the committed ciphertext to its recovery KMS
   key. The relay returns an RSA-OAEP-SHA-256 ciphertext for the approved target
   key. Provision the target with the usual command. Its KMS call uses the
   manifest's algorithm. Asymmetric KMS calls carry no encryption context.
   The immutable per-slot key ARN and the enclave's share commitment identify
   the slot. [KMS GetKeyPolicy](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetKeyPolicy.html) · [KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html)

A relay-pinned epoch requires RSA destinations and another relay-pinned epoch
when rotating. Its source keys stay bound to the measured epoch relay and its
approval roster. During a roster change, the active quorum registers the
successor target and the successor's measured quorum approves each relay wrap.
Commission the successor and retire the old source keys before the roster
cutover. The wrapping tool refuses a source relay whose measured quorum has
retired. A running source relay trusts its measured roster until its boot ends.
The wire authorization signs the SHA-256 of
`SPR/native-nitro/relay-release/v1` followed by a null byte and canonical
statement JSON. KMS signatures retain DER encoding. Live six-account
qualification and the approval-roster cutover drill are pending.

The signed statement sets `expiresAt` to the earlier of the target's approval
deadline and the next scheduled approval-roster activation, in Unix seconds.
The relay reads the timestamp directly from its Nitro Secure Module before
opening the share and again before returning ciphertext. Either failed clock
read rejects the request. Stop the source relay and revoke its KMS access if
the epoch closes ahead of schedule. Ciphertext already delivered to an approved
target remains subject to that target's KMS policy.
[Nitro attestation document fields](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html#term-attestation-document)

## Replace a compromised seed

1. Freeze new sends that resolve through the old service. Initialize a fresh
   domain with a newly generated seed and an independent release namespace.
   Commission its serving slots and publish an activation with
   `recoveryOnly: false`. Verify both buckets and the serving replicas before
   distributing the new send pins.
2. Publish `recoveryOnly: true` in the next old-domain policy. If recovery
   replicas are offline, publish a target-free revocation with the flag set.
   Publish a recovery-only activation once the old replicas are ready. Preserve
   `recoveryOnly: true` in all later old-domain policies. Pin the flag and the
   cutover sequence when distributing old-domain recovery trust to wallets.
3. Keep the old domain available for owner-signed recovery. Open it with the
   recovery pins, scan the owner's outputs, verify commitments, and sweep to
   wallet-local notes. Switch new sends to the new domain. Rehearse both paths
   using [the on-chain devnet procedure](../../../tests/README.md#live-seed-cutover).
   Retain the old recovery capability until affected owners have a recovery
   path. Treat previously exposed note data as compromised.

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

The canonical envelope starts with `{"custodySignatures":[],"policy":...,"signatures":[]}`. Its policy
fields are `version`, `action`, `network`, `securityDomainId`, `noteSeedCommitment`,
`minimumCustodyEpoch`, `sequence`, `previousPolicyDigest`, `validFromMs`, `expiresAtMs`, `recoveryOnly` and `targets`.
Sequence 1 has `previousPolicyDigest: null`. Each later sequence signs the
digest of the current published policy. Use the domain-separated policy
digest specified in [the Nitro security spec](../../NITRO.md#proposal-and-publication).
Each target contains `endpoint`, `releaseId`, `executableSha256`,
`custodyEpoch`, `custodyDigest` and `pcrs`. Obtain `custodyDigest` with
`python3 "$nitro/custody_ledger.py" trust.json read "$epoch" --custody-digest`.
Register each serving target before signing an activation. The signing and
publication tools match its executable, release ID and PCR0–PCR3 to the
registered serving image and verify its committed, active custody epoch.
Give release signers, custody signers and both publishers scoped ledger read
access using `reader-policy`. Distribute the custody trust file independently.
For activation, collect release signatures and two custody signatures from the
active custody approval roster. Each signer checks the exact proposed targets.
For revocation, leave `custodySignatures` empty and omit `--custody-trust`.

Pin network, domain, seed commitment, minimum sequence, minimum custody epoch,
release `keys` and `threshold`, the three `custodyKeys`, and `publications` with
two `{bucket, region, account}` entries in `wallet-trust.json`. The key lists
must be disjoint and use uncompressed SEC1 hex. Export that format with
`python3 "$nitro/approval.py" "$key_arn" --sec1`. List the primary bucket first.
Times, sequence and epochs are canonical decimal strings. The wallet stores the
sequence, policy digest, custody floor and recovery mode atomically. Normal
activation requires a verified replica before the wallet advances the
checkpoint. A recovery-only policy advances the checkpoint when the signatures
verify, before any replica attests. An emergency `revoke`
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
cargo xtask nitro-sign policy.json --custody --key "$custody_key_arn" --public-key "$custody_sec1_hex" --custody-trust "$custody_trust"
cargo xtask nitro-sign policy.json --key "$signing_key_arn" --public-key "$signer_sec1_hex" --custody-trust "$custody_trust"
pnpm --dir example exec tsx ../xtask/nitro-publish.ts "$wallet_trust" "$bucket" --bucket-policy "$bucket_admin_role" "$publisher_role"
pnpm --dir example exec tsx ../xtask/nitro-publish.ts "$wallet_trust" "$bucket" "$signed_policy" --custody-trust "$custody_trust"
```

Wrap-key replacements for a new EIF use the existing receipt and new sealed key
ARNs. Custodian replacements use a measured rotation.

### Rotate wallet signing keys

1. Have the outgoing and incoming quorums for the rotating authority sign the
   same next revision. For a custody roster change, collect outgoing signatures
   before the operator cutover and incoming signatures after it. Keep the domain,
   bucket pins and custody floor, and allow time to complete the rollout before
   the current wallet policy expires.
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
