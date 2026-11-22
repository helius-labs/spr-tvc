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
The three approval keys are separate P-256 KMS keys in three independently
administered accounts. Sign with KMS and verify the signatures locally with OpenSSL.
Export public keys as `{keyArn, publicKey}` with `python3 enclave/deploy/nitro/approval.py "$key_arn"`.

Pin `trust.json` outside the host and artifact distributor. It contains
`network`, `securityDomainId` (32 random bytes in lowercase hex), `approvalKeys`,
`recoveryRelays`, and `ledger` with `bucket`, `region` and `account` (the
12-digit bucket owner's account ID). Each `approvalKeys` entry contains `fromEpoch`, `activeFrom`
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
ownership, all four bucket public access blocks enabled, and no lifecycle or
replication configuration. Check the installed controls with the same role list
before publishing custody records.

```sh
python3 "$nitro/custody_ledger.py" trust.json policy "$ledger_admin_role" "$publisher_role" "$reader_role" --check-installed
```

Run the check with AWS CLI v2 supporting `--cli-error-format json` and with
credentials in the pinned bucket owner's account. The inspection identity
needs `s3:GetBucketPolicy`, `s3:GetBucketVersioning`,
`s3:GetBucketOwnershipControls`, `s3:GetBucketPublicAccessBlock`,
`s3:GetLifecycleConfiguration`, and `s3:GetReplicationConfiguration` on
the ledger bucket. S3 lifecycle rules can expire records independently of the
delete permissions in the bucket policy. [S3 lifecycle documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/troubleshoot-lifecycle.html)

The policy restricts administration to a separate role and allows
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

Before creating the recovery keys, build the epoch's relay EIF with
`deployment: {"mode":"relay","custodyEpoch":"1","approvalKeys":[...]}`.
Supply the three uncompressed SEC1 public keys in epoch roster order. Use
the same build and review procedure as the custody EIF below. In
`recoveryRelays`, pin the relay's `hostRole` and `pcrs` (PCR0–PCR2) under its
epoch string. The tools derive PCR3 from the relay host role. Add new epoch
entries as custody rotates and preserve the historical pins.

Render the recovery policies after pinning the relay. Install each custodian's
two policies at key creation with `--bypass-policy-lockout-safety-check`.
The recovery key permits only the custodian role and requires attestation from
the measured relay. The acknowledgement key permits only the custodian role
to sign. Give the approvers read-only profiles in all six slot accounts with
`kms:DescribeKey`, `kms:GetKeyPolicy` and `kms:GetPublicKey` on the keys they
inspect. AWS KMS requires `GetKeyPolicy` to run in the key's own account.
Custody approval checks each profile's actual AWS account through STS before
inspecting that slot's keys.
[GetKeyPolicy permissions](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetKeyPolicy.html)

## Commit a custody epoch

Install the repository's pnpm dependencies on the approval, custodian and
publisher hosts. All three roles run the Nitro evidence verifier locally.

1. Create `configuration.json` with `releaseId`, `securityDomainId` and
   `deployment`. Initialization uses `{"mode":"initialize","recipientPublicKeys":[...]}`.
   Each recipient is the lowercase-hex DER SPKI of its RSA recovery key, in roster order.
   The EIF workflow statically links the pinned OpenSSL 3.5 LTS source, checks
   the linked version, and runs the measured binary against the exact
   configuration before packaging.
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
   attestation, archived AWS evidence, and the attested relay's build, PCRs
   and ordered signer keys. Each approver checks both installed policies and
   public keys in all six slots. Pass each updated document to the next
   signer. Each custodian independently verifies the ceremony build and Nitro
   evidence using the reviewed commit and ref, then acknowledges in its own
   account after the measured relay proves possession of its committed share.
   Forward the relay's vsock
   port 44031 through SSM to a loopback port. It serves for ten minutes.
   Publish the fully acknowledged document with the dedicated publisher role.

   ```sh
   python3 "$nitro/custody_ledger.py" trust.json sign epoch-draft.json "$build_dir" "$approval_key" \
     epoch-signed.json --source-commit "$reviewed_commit" --source-ref "$source_ref" \
     --relay-build "$relay_build" "$relay_commit" "$relay_ref" \
     --inspection-profiles "${inspection_profiles[@]}"
   python3 "$nitro/custody_ledger.py" trust.json acknowledge epoch-signed.json "$build_dir" "$share_index" epoch-ack.json \
     --relay-port "$port" --source-commit "$reviewed_commit" --source-ref "$source_ref"
   python3 "$nitro/custody_ledger.py" trust.json publish epoch-ack.json
   python3 "$nitro/custody_ledger.py" trust.json read 1 > receipt.json
   ```

   `publish` verifies the Nitro evidence, two approvals and all six
   acknowledgements on the same candidate. The first successful conditional write fixes the receipt for that
   epoch and its recovery relay. A rotated receipt pins the previous receipt
   and the registered rotation approval. Drafting and signing check the measured configuration.
   Acknowledgement, publication and online reads verify the same image, host
   role and successor roster. The seed commitment stays stable.

   Export the custody history through the committed epoch and record the
   SHA-256 of the complete file in an independently retained audit record.
   Keep the pinned custody trust schedule and the reviewed build artifacts
   with the archive. The verifier opens no AWS connection. It checks the
   genesis receipt, each rotation link, original target approval and
   recorded S3 publication time, custodian signatures and Nitro evidence at
   its recorded verification time. The independent archive pin authenticates
   the exported S3 timestamps.

   ```sh
   python3 "$nitro/custody_archive.py" trust.json export "$epoch" > custody.jsonl
   shasum -a 256 custody.jsonl
   python3 "$nitro/custody_archive.py" trust.json verify "$epoch" custody.jsonl "$pinned_sha256"
   ```

   Pause ledger publication and drain in-flight writes. Render and install the
   bucket policy with `--frozen` to deny all writes in the custody prefix. Let
   the policy propagate and verify the installed controls with
   `--frozen --check-installed`. Keep that policy in place while recording and
   comparing checkpoints. The checkpoint command verifies the write deny and
   absence of lifecycle rules before and after reading the records.
   [S3 consistency model](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html)

   Include the inspection role from the bucket owner's account in the reader
   list. Give its IAM identity policy
   `s3:GetBucketPolicy`, `s3:GetLifecycleConfiguration`, `s3:ListBucket` on the full
   custody prefix, and `s3:GetObject` on its records. Retain the digest
   independently with evidence of the last committed write. The digest covers
   every receipt, target registration and retirement marker, including each
   object's original version ID, write time and exact bytes. Keep the pinned
   approval schedule and relay keys when updating the bucket, owner and region
   in the recovered trust file.

   ```sh
   python3 "$nitro/custody_ledger.py" trust.json policy "$ledger_admin_role" "$publisher_role" "$reader_role" --frozen > ledger-frozen-policy.json
   python3 "$nitro/custody_archive.py" trust.json ledger-checkpoint
   python3 "$nitro/custody_archive.py" recovered-trust.json ledger-checkpoint --expect "$ledger_checkpoint_sha256"
   ```

   Suspend registration, share release and key retirement if the canonical
   ledger becomes unavailable or incomplete. Resume only after the recovered
   bucket matches an independently retained checkpoint covering all committed
   writes. Keep the original ledger's write fence in force while promoting
   the recovered bucket. Install and verify the normal writable policy on the
   recovered bucket before resuming.
   AWS Backup creates new object creation dates and version IDs on restore.
   [AWS Backup metadata](https://docs.aws.amazon.com/aws-backup/latest/devguide/s3-backups.html)

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
   custody accounts, install the final wrapping policy on a fresh
   KMS-generated RSA `ENCRYPT_DECRYPT` key per slot. Render the policy with
   `kms_policy.py` using the build measurements, `--instance-id`, and exact host, custodian and
   retirement roles. Keep the returned immutable ARNs in `wrapping-keys.json`,
   an array in roster order. Choose an approval deadline in Unix seconds.
2. Two approval signers independently check and sign the target manifest. It
   binds the canonical receipt, mode, EIF, configuration, measurements, parent
   account, EC2 region and instance ID, and six wrapping keys. Each signer uses
   a read-only profile with `ec2:DescribeInstances` in the host account to
   confirm that exact parent is running with enclave support enabled. Supply
   six read-only profiles in slot order to verify the installed wrapping
   policies and RSA key metadata before signing. A rotation draft takes
   `--next-roster roster-next.json` and binds the successor relay from custody trust. Before authorizing a
   rotation, both signers verify the successor's build and keys with
   `--next-relay-build BUILD COMMIT REF` and `--next-inspection-profiles`.

   ```sh
   python3 "$nitro/deployment.py" trust.json "$build_dir" draft "$host_role" wrapping-keys.json \
     "$approval_deadline" --host-region "$host_region" --instance-id "$instance_id" > target-draft.json
   python3 "$nitro/deployment.py" trust.json "$build_dir" sign target-draft.json "$approval_key" \
     target-signed.json --source-commit "$reviewed_commit" --source-ref "$source_ref" \
     --host-inspection-profile "$host_read_profile" \
     --inspection-profiles "${inspection_profiles[@]}"
   python3 "$nitro/deployment.py" trust.json "$build_dir" register target-signed.json
   python3 "$nitro/deployment.py" trust.json "$build_dir" host-policy target-signed.json > host-kms-policy.json
   python3 "$nitro/deployment.py" trust.json "$build_dir" attestation-pins target-signed.json > pcrs.json
   ```

   Register with the dedicated ledger publisher more than 30 seconds before
   the approval deadline. The ledger verifies that S3 recorded the first
   registration before expiry. It keeps the signed target and all six
   wrapping-key ARNs. Within an epoch, a release ID
   and PCR0–PCR4 identify one wrapping-key set. Each parent needs its own set.
   Use a fresh release identity to replace keys for the same image and parent.
   A fresh approval can renew the wrapping deadline
   without replacing the registered target. Use [Share release](#share-release)
   to produce more than three wraps so a new boot can tolerate unavailable
   keys.
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
   shares. Use the rotation target's `attestation-pins` output for the
   ceremony capture. Commit the new receipt after all six keys acknowledge it.
2. Commission serving slots from the new receipt on separate EC2 parents. On a fresh enclave run,
   pass `--slots 2 4 6` to `provision.py` to use only those three current slots.
   Provisioning fails if any selected slot fails. Save the three slots that
   the enclave reports using to restore the seed. Readiness has a 20-second
   deadline. Each provisioning and relay HTTP exchange has an eight-second
   deadline for connection, request and reply. If the submission result is
   unconfirmed, verify serving attestation or the rotation receipt before
   restarting.
   Through the real ingress, use the wallet to open a note
   addressed before rotation. Keep healthy old slots during qualification.
3. Allow overlap while the wallet policy floor covers both epochs. After a
   cold boot and wallet canary on the new epoch, publish a policy with
   `minimumCustodyEpoch` at the new epoch. Drain old sessions and terminate
   every parent registered to serve or rotate the old epoch. An older executable can be built for the current epoch if needed.
4. Pin the file SHA-256 of the independently distributed wallet trust bundle
   as `walletTrustSha256` in the custody trust file. The retirement draft
   records the replacement's attested boot key ID, Nitro bootstrap time and
   actual bootstrap slots.
   The three custodians named by those slots run `prove-recovery` in their
   respective roles. Each command reopens that custodian's package from the
   replacement receipt and signs the candidate with its acknowledgement key. Keep those keys enabled for the
   current epoch. Pass each output to the next custodian.

   Two custody approval signers then sign, and the ledger publisher commits
   the record within 24 hours of the replacement boot. Signers and the
   publisher need `kms:DescribeKey` on the recovery and target wrapping keys
   for those exact three slots. All six keys must still be enabled. Draft, sign
   and publish require the same signed policy file in both buckets before and
   after attestation and match the replacement to its registered serving
   target. If the attested boot key or slots change, draft
   a new candidate and collect proofs for those slots. After a timeout, retry the same signed
   document. The tool verifies a committed record against its historical
   roster and S3 timestamp, even after the recovery window closes. If the
   write never committed and the window or policy changed, draft a new
   candidate. A committed record closes the old epoch to new wraps. Its key
   inventory includes wrapping keys registered before the commit, including
   those for requests in flight.

   ```sh
   python3 "$nitro/retirement.py" trust.json draft wallet-trust.json 1 2 > retire-draft.json
   python3 "$nitro/retirement.py" trust.json prove-recovery retire-draft.json 2 --relay-port "$port" > retire-proof-1.json
   python3 "$nitro/retirement.py" trust.json prove-recovery retire-proof-1.json 4 --relay-port "$port" > retire-proof-2.json
   python3 "$nitro/retirement.py" trust.json prove-recovery retire-proof-2.json 6 --relay-port "$port" > retire-proof-3.json
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
   Give the verifier a KMS inspection profile for each old custody account
   in slot order and an EC2 inspection profile for each old parent account.
   It checks the accounts through STS before reading the retirement inventory. Add
   `cloudtrail:LookupEvents` to a custody inspection profile to verify keys
   after permanent deletion. The verifier requires the exact key's AWS KMS
   `DeleteKey` service event and includes its ID in the report. CloudTrail
   event history covers 90 days, so collect the retirement report within
   that window. [KMS deletion event](https://docs.aws.amazon.com/kms/latest/developerguide/ct-delete-key.html)
   · [CloudTrail event history](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html).
   Enable AWS Config recording of `AWS::EC2::Instance` before commissioning
   and give each host inspection profile `config:GetResourceConfigHistory`.
   Use an operator host with a synchronized clock.

   ```sh
   python3 "$nitro/retirement.py" trust.json verify-retired wallet-trust.json 1 \
     --inspection-profiles "${old_inspection_profiles[@]}" \
     --host-inspection-profile "$old_host_account=$old_host_read_profile" \
     --output "$retirement_report"
   ```

   When the verifier reports it is waiting, cold-boot a registered replacement
   with exactly three slots. The verifier reads the candidate registrations
   before starting the `--wait-seconds` timer and polls for a later attested
   boot. Before writing the report it checks the old keys and parents again,
   checks the six keys used by the new boot, and verifies the same registered
   boot and wallet policy. Pass a new report path. The complete file appears
   only after verification succeeds. AWS usually lists terminated instances
   for less than an hour. When EC2 cannot report a parent, the verifier
   requires that the latest AWS Config record
   for that exact managed EC2 instance is `ResourceDeleted`. Archive the
   result with the [on-chain canary](../../../tests/README.md#live-nitro-upgrade),
   old signed receipt and public trust pins.
   [EC2 instance visibility](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html)
   · [AWS Config history](https://docs.aws.amazon.com/config/latest/APIReference/API_GetResourceConfigHistory.html)
   · [KMS key states](https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html)

## Share release

For each slot, two epoch approval signers authorize the exact relay boot and
sealed destination public key. Both use a read-only inspection profile in the
slot account. Each command reattests the relay and checks the installed target
policy. Collect both signatures against the same boot. Before opening a share,
the custodian verifies GitHub provenance for the exact reviewed commit and
ref they received independently. The custodian checks the installed recovery
policy, sends the recovery package and relay
attestation to KMS, and passes the encrypted response to the relay. The relay
checks the signatures, share commitment and authorization deadline, then
returns an RSA-OAEP-SHA-256 ciphertext for the registered destination.

```sh
python3 "$nitro/relay_wrap.py" trust.json target-signed.json "$build_dir" "$slot" --relay-port "$port" \
  draft --inspection-profile "$slot_read_profile" > relay-draft.json
python3 "$nitro/relay_wrap.py" trust.json target-signed.json "$build_dir" "$slot" --relay-port "$port" \
  sign relay-draft.json "$first_approval_key" --inspection-profile "$slot_read_profile" > relay-signed-1.json
python3 "$nitro/relay_wrap.py" trust.json target-signed.json "$build_dir" "$slot" --relay-port "$port" \
  sign relay-signed-1.json "$second_approval_key" --inspection-profile "$slot_read_profile" > relay-signed-2.json
python3 "$nitro/relay_wrap.py" trust.json target-signed.json "$build_dir" "$slot" --relay-port "$port" \
  wrap relay-signed-2.json "shares/$slot.kms" \
  --source-commit "$reviewed_commit" --source-ref "$source_ref"
```

During an approval roster change, the active quorum registers the successor
target and the successor's measured quorum approves its relay wraps. Commission
the successor and retire the old source keys before the cutover. The wrapping
tool refuses a retired roster. Stop the source relay and revoke its KMS access
if the epoch closes early. A running source relay trusts its measured roster
until the boot ends.

The wire authorization signs the SHA-256 of `SPR/native-nitro/relay-release/v1`
followed by a null byte and canonical statement JSON. KMS signatures retain DER
encoding. The signed `expiresAt` is the earlier of the target deadline and next
scheduled roster activation in Unix seconds. The relay reads Nitro time before
opening a share and again before releasing ciphertext. A failed clock read
rejects the request. Ciphertext already delivered to the target remains subject
to its KMS policy. [Nitro attestation](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html) · [KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html)

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
`custodyEpoch`, `custodyDigest` and `pcrs`. Use `attestation-pins` from
the registered target for `pcrs`. Obtain `custodyDigest` with
`python3 "$nitro/custody_ledger.py" trust.json read "$epoch" --custody-digest`.
Register each serving target before signing an activation. The signing and
publication tools match its executable, release ID and PCR0–PCR4 to the
registered serving image and verify its committed, active custody epoch.
Both publishers require the activation's wallet custody pins to match the
active roster in their independently distributed custody trust file. They
leave at least 30 seconds before a scheduled roster cutover to submit the S3 write.
Give release signers, custody signers and both publishers scoped ledger read
access using `reader-policy`. Distribute the custody trust file independently.
Collect the release quorum and two custody signatures on every policy.
For activation, each signer checks the approved targets. For an emergency
revocation, sign the target-free policy with both quorums and omit
`--custody-trust`. Revocation needs access to the signing keys and publication
buckets, even when the ledger and replicas are offline.

Pin network, domain, seed commitment, minimum sequence, minimum policy digest,
minimum custody epoch,
release `keys` and `threshold`, the three `custodyKeys`, and `publications` with
two `{bucket, region, account}` entries in `wallet-trust.json`. The key lists
must be disjoint and use uncompressed SEC1 hex. Export that format with
`python3 "$nitro/approval.py" "$key_arn" --sec1`. List the primary bucket first.
The `minimumPolicyDigest` is the release signing digest printed by
`cargo xtask nitro-sign` for the pinned `minimumSequence`. Times, sequence and
epochs are canonical decimal strings. The wallet stores the
sequence, policy digest, custody floor and recovery mode atomically once
it verifies both signed heads, before contacting a replica. An activation
still requires fresh replica attestation before use. A revocation has an
empty target list. Each publisher checks the predecessor, verifies
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

Before distributing a wallet trust file, run this read-only check. It requires
both buckets to serve the exact same signed file at the pinned revision, with
the expected custody floor and recovery mode. Run it with scoped custody ledger
read access for an activation. It verifies the registered serving targets and
active roster, then rechecks both buckets. For a target-free revocation during
a ledger outage, omit `--custody-trust`. Use the reported `trustSha256` to
identify the exact file in the wallet release.

```sh
pnpm --dir example exec tsx ../xtask/nitro-publish.ts "$wallet_trust" --check-wallet-trust --custody-trust "$custody_trust"
```

Wrap-key replacements for a new EIF use the existing receipt and new sealed key
ARNs. Custodian replacements use a measured rotation.

### Rotate wallet signing keys

1. Have the outgoing and incoming quorums for the rotating authority sign the
   same next revision. For a custody roster change, collect outgoing signatures
   before the operator cutover and incoming signatures after it. Keep the domain,
   bucket pins and custody floor, and allow time to complete the rollout before
   the current wallet policy expires.
2. Pin the transition sequence and its `minimumPolicyDigest` in the incoming trust.
   Publish the same signed file to both buckets using the outgoing trust and
   pass `--next-trust "$incoming_trust"` to each publication. The tool checks
   both sets of pins before writing. For custody rotation, publish the
   activation after the incoming roster activates. Distribute the incoming trust after both
   copies are in place.
3. After wallets adopt the new trust, publish the next revision with the incoming
   quorum and retire the outgoing keys.

If the outgoing quorum is unavailable or compromised, independently
distribute incoming trust pinned to the successor's sequence and digest. Publish under
that trust with `--emergency-from "$outgoing_trust"` to authenticate the
existing predecessor. The successor needs both quorums under the incoming
pins. Wallets resume once they use the new trust and both buckets publish
the successor.

[Security model](../../NITRO.md) · [Test invariants](../../../tests/INVARIANTS.md) · [Audit handoff](../../../tests/AUDIT.md)
