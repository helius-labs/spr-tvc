# Native Nitro security specification

SPR senders can encrypt an output for a wallet that has no registry entry. The service derives the wallet's viewing and nullifier keys from a stable, network-specific seed and the owner's Solana address. See [the request and output specification](SPEC.md) for canonical messages, owner authorization, output handling and SDK commitment checks.

## Trust and custody

| Actor | Authority |
| --- | --- |
| Wallet owner | Signs a decrypt batch and the response public key. The matching response private key opens its reply. |
| Six note-share custodians | Each controls one sealed RSA recovery key in its own AWS account. All six sign recovery acknowledgements before a custody epoch is committed. Three shares can then commission an approved target or rotate custody. |
| Custody approval signers | Two of three pinned KMS keys approve the custody record or authorize release of shares to one measured target. The custody ledger admits one record per epoch. |
| Release signers | At least two distinct pinned P-256 keys authorize a policy. Use two of three separately controlled KMS signing keys. Each signed target names an HTTPS route, release ID, executable SHA-256 and PCR0–PCR4. |
| EC2 parent and ingress | Can choose when and where to forward requests, and can deny service. See note ciphertexts, wrapped shares, TLS metadata, timings and sizes. Never receive note plaintext or a private key via the protocol. |
| AWS Nitro, KMS and S3 | Nitro isolates enclave memory and signs evidence. KMS enforces key policies. S3 serializes conditional ledger writes. The bucket policies separate object publishers from bucket administration. Account root and the separate bucket administrator remain trusted. |
| Policy publishers | Each controls one pinned S3 bucket in a separate AWS account. They publish the same signed release policy independently. Either can interrupt service. Once both publish a policy, replay by one publisher cannot make a wallet use an earlier policy. |
| Wallet integration | Distributes both publication pins, network, security domain, note seed commitment, release threshold, minimum release sequence, minimum custody epoch, and separate release and custody signer pins. Stores the highest accepted sequence, policy digest, custody floor and recovery mode in durable atomic state. |

Commissioning requires two approvals of the exact target and three custodian shares. Wallets separately require a signed release policy and fresh attestation. A malicious enclave with three shares can disclose the seed even if wallets refuse to connect. Review the source and the measured artifact before approving share release. Account administration and role assumption must preserve the independence of custodians and approval signers.

Each custodian can ask KMS to release one share to the epoch's measured relay.
The signed custody receipt pins the relay and its host role. Custody approvers
verify its build, ordered signer roster and the installed recovery and
acknowledgement key policies for each slot. The approval and acknowledgement
keys are distinct.
The relay checks the share commitment and requires two approvals of the exact
target key, relay boot and deadline. It reads Nitro time before opening the
share and again before returning ciphertext. The approved target obtains its
share through a second attested KMS decrypt. Fresh relay evidence confirms
recovery before the operator tool uses the custodian's acknowledgement key.
The ledger verifies the custodian's signed assertion over the candidate.

During roster rotation, the active quorum signs target registration and the
epoch's measured quorum signs share releases. Retire the old source keys and
stop their relay before switching rosters. See the [share-release procedure](deploy/nitro/README.md#share-release).

Custody and target signers require GitHub build provenance from the designated
native EIF workflow at the exact ref and commit approved in review. Devnet can
use an explicit branch in this repository. Mainnet requires a fresh dispatch
from protected `main` and an `image-publish` approval from a GitHub user other
than the dispatcher. The build shows the immutable artifact and its hashes
before review. The workflow attests the executable, configuration, EIF and
PCR0–PCR2 hashes after verifying the approval. Signers verify a private copy of
the exact provenance bytes and match their proposed target or ceremony against
the authenticated hashes. The KMS wrapping policy pins PCR3 to the parent IAM
role and PCR4 to the EC2 instance ID. Each wrapping-key set serves a single
parent. A replacement parent needs its own approval and wrapping keys, even
when it runs the same EIF. Recovery keys still pin the measured relay and its
role. The relay handles one share and can only wrap it to its approved target.

## Custody and startup

An initialization EIF measures the network, security domain and six ordered RSA
recipient public keys. It generates the 32-byte seed inside Nitro and uses
3-of-6 Shamir secret sharing over GF(256). Each share encodes its custody epoch
as eight big-endian bytes, its one-byte index and the 32-byte share value.
The seed identity is SHA-256 over `SPR/native-nitro/note-seed/v1`, the domain
and the seed. Each share commitment hashes
`SPR/native-nitro/custody-share/v1`, the domain and that share's encoded bytes.

A custody rotation EIF measures the previous custody record and the six keys
authorized for the next epoch. It reconstructs the existing seed from three
valid previous shares and issues six fresh shares at the next epoch. It
publishes the same seed commitment, six share commitments and one RSA-OAEP
SHA-256 ciphertext per recipient. It erases the seed and serves the result
for up to five minutes. Each receipt binds a verifier nonce and
`SHA256("SPR/native-nitro/custody/v1" || canonical result)` in Nitro evidence.
The ceremony serves only the custody port. Its measured recipient list controls
where shares can be sent. A reboot can issue a different record for the same
epoch. The capture retains the original evidence, challenge and verification
time. Two approval signers reverify the proof and bind the record to the six
recovery keys, measured relay and exact predecessor. Before opening its
share, each custodian verifies the evidence and build provenance against an
independently reviewed ref and commit. The publisher verifies the Nitro proof
before committing the signed record. A rotated receipt pins
the registered rotation approval. It must match the approved rotation image,
host role, successor roster and successor relay. All six custodians sign an
acknowledgement that their sealed key can open its share.
A conditional S3 write commits one record for
the epoch. Historical receipts verify with the public keys pinned for their
epoch. Target approvals and retirement records verify under the roster
active at the original S3 write. Publishing after a cutover requires
approval from the incoming roster. Retiring an approval or acknowledgement
signing key leaves custody receipts verifiable offline. The archive checks
the independently pinned digest of the entire history, each predecessor link
and registered rotation approval, and each ceremony’s Nitro proof at its
recorded verification time.

The custody ledger registers one wrapping-key set per epoch, release ID and
PCR0–PCR4. Before signing, each approver checks that all six RSA wrapping
keys have the installed policy for the exact parent and measurements. At
first registration the ledger checks the domain and committed receipt. S3
must record the write within the approval window. A new quorum approval may renew the deadline for the same set. Each share release
checks the registered target and both installed KMS key policies. The
custodian verifies build provenance against its independently reviewed ref
and commit before requesting KMS recovery. The tool checks the epoch, roster
and deadline around KMS and relay calls. The relay
opens the share and wraps it to the approved RSA key inside Nitro.

The wallet publishers raise the custody floor after the replacement attests.
The replacement enclave attests the three distinct slots used to restore the
seed, its boot transport key ID and the Nitro time after restoring the seed.
Those exact three custodians reopen their
committed recovery packages and sign the retirement candidate with their
acknowledgement keys. Their proofs bind the boot, both receipts, the wallet
policy, the registered serving target and the deadline 24 hours after its
bootstrap. Signers and the publisher reattest the same boot and confirm
that both the recovery and target wrapping keys for its three slots remain
enabled. Restarting the replacement before publication requires a new
candidate.
The ledger checks the S3 write time against the proof window and verifies
both receipts, the signatures and the target before producing the key
inventory. An unverifiable record halts new wraps and requires ledger recovery.
A reconstructed seed remains in enclave memory until the enclave stops.
Use replacement parents separate from those registered for the old epoch.
The read-only retirement verifier checks the old key inventory in all six
accounts and requires each registered old serving or rotation parent to be
terminated. It then checks for a later attested replacement boot and repeats
the old key and parent checks. When EC2 no longer lists a parent, the
verifier requires its AWS Config deletion record for the exact managed EC2
resource. Record the on-chain canary with the report.
The report concerns the registered targets and their sealed policies. A
seed disclosed before retirement requires a new seed domain.

A serving EIF measures its network, release, security domain and current
custody record. Both serving and rotation use the same bootstrap:

1. The enclave creates a temporary RSA-2048 recipient and attests its public
   key on vsock port 44031. The parent calls KMS with that evidence and each
   wrapped share. The host's inline IAM policy and each sealed key require
   RSA-OAEP-SHA-256 and PCR0–PCR4. The host gets the six ordered key ARNs
   from the approved target pinned by file hash. The enclave checks the
   domain, epoch and slot against the measured share commitments.
2. KMS encrypts its response for that temporary recipient. The parent sends up
   to six CMS records. Each starts with a one-byte slot and a two-byte
   big-endian length, followed by up to 6,144 bytes of ciphertext. A share
   contributes only if its decrypted slot matches the frame and its epoch
   and commitment match the measured configuration. The enclave restores
   the seed from three distinct slots and verifies the seed commitment. It
   replies with HTTP 200 and the three slot numbers as raw bytes. A serving
   enclave keeps those same slot numbers for wallet attestation. Invalid
   framing fails the batch and another request can retry.
3. Boot expires after two minutes. Successful boot drops the RSA recipient.
   A serving enclave generates fresh P-256 request-encryption and
   response-signing keys and listens on vsock port 44030. The boot transport ID
   is SHA-256 of the public pair. The native wire epoch names the custody epoch.

See [Shamir secret sharing](https://doi.org/10.1145/359168.359176),
[KMS recipient handling](https://docs.aws.amazon.com/kms/latest/developerguide/attested-calls.html)
and [attestation conditions](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html).

## Proposal and publication

The policy digest is SHA-256 of the UTF-8 string
`SPR/native-nitro/release-policy/v1` followed by RFC 8785 canonical policy JSON.
Release signers sign this digest. Every policy after sequence 1 includes the
previous published digest. Signers and publishers independently verify that
each activation target matches an active epoch, the committed custody receipt,
and a custody-approved serving executable, release ID and PCR0–PCR4. Two of
three independently pinned custody approval keys also sign the entire
policy. Their digest uses `SPR/native-nitro/custody-release-policy/v1`
followed by the same canonical JSON. The SDK verifies both quorums before
contacting a replica. Separate key pins prevent the release quorum from
substituting its own recipient keys through an unapproved image. Each publisher
also checks the predecessor and attests every activation target. A revocation
has no targets. Its sequence, custody floor and recovery flag can permanently
change wallet state, so it also requires both quorums.
Revocation can proceed while the custody ledger and replicas are offline.
S3 accepts a write against the checked predecessor's ETag. Each publisher
writes to its own bucket. The mirror copies the primary's signed file, including
all signatures. The primary checks that the mirror holds the same file before
advancing again. The enclave and ingress have no publication permission.

Wallets pin both buckets, regions and AWS owners. They read directly from both
without caching or redirects and authenticate both policies. Equal digests
agree. During rollout the primary can advance by one signed revision with a
nondecreasing custody floor while the mirror serves its exact predecessor.
The primary's policy authorizes the connection. A mirror that is ahead, a
missing or invalid head, a fork, a gap or an expired primary blocks new
connections. Both buckets must agree before custody retirement qualifies a
replacement. The verifier checks agreement again after attestation.

Shipped pins bind the minimum sequence to its exact policy digest. The
immediate successor must name that digest as its predecessor. The checkpoint
transaction applies the same rules to both heads it has authenticated.
A wallet that missed more revisions than those heads expose relies on the
independent publishers and signing quorums for the skipped history. Local
checkpoints, shipped pins and policy expiration limit replay by both publishers.

The envelope carries `policy`, `signatures` and `custodySignatures`. Each list
can carry up to eight distinct valid low-S P-256 signatures. A key can appear in
only one list. Wallets count only their pinned keys for that list. For a
planned signer rotation, the publisher verifies the same signed revision
under both the outgoing and incoming trust. The incoming minimum sequence and policy digest pin the transition revision. Publish it to both buckets before distributing
the incoming pins.

## Seed compromise and recovery

A share rotation preserves the note seed. Exposure of three shares from one
epoch can expose past and future notes in that seed domain. Bring up a new
domain with a freshly generated seed and independently distributed wallet pins.
Use it for new destinations. Publish `recoveryOnly: true` on the old domain.
Wallets persist that restriction once the signed policy verifies, even if no old
replica attests. Later policies, including emergency revocations, must retain
it. A fresh or restored wallet pins `recoveryOnly: true` and the minimum
cutover sequence for the old domain.

The old client rejects `address()` and still supports the owner's signed
`open()` flow against an attested replica. Owners scan old notes and sweep to
wallet-local privacy keys under their own signatures. Stopping destination
lookup protects supported wallets after they observe the cutover. A cached
wallet session can take up to 60 seconds to refresh. A permissionless sender
can still pay a previously published destination. Earlier ciphertexts retain
their exposure, and owners must retain access to the old domain until recovery
is complete. [Cutover runbook](deploy/nitro/README.md#replace-a-compromised-seed)

## Wallet connection and operations

1. Fetch both policies with a five-second deadline and a 32 KiB limit per response. Require both quorums on each head. Check the network, domain, seed commitment and allowed lifetime. Atomically advance the wallet's durable checkpoint to the authenticated primary before contacting any replica. An `activate` policy lists eligible replicas. A `revoke` policy has an empty target list and returns `ReleasePolicyRevoked` after the same checkpoint write.
2. POST a random 32-byte nonce to each attempted authorized target's `/v1/nitro/attestation`. Schedule fallback probes 200 ms apart and advance immediately when the preceding probe fails. Use the first verified boot and cancel unused probes. Each reply includes `boot` and AWS-signed COSE `evidence`. The `boot` object contains `info`, the three `bootstrapSlots` that restored this replica, and `bootedAtMs` as a decimal string from the Nitro Secure Module. The document signs the nonce, SHA-256 of `SPR/native-nitro/discovery/v1` followed by the canonical `boot` object, and the replica's response-signing public pair.
3. Verify the exact pinned AWS root, the current certificate path and usages, the ES384 COSE signature, the signed timestamp and nonce, PCR0–PCR4 and the discovery bindings. Verify both public pairs before use. Compute the discovery release digest as SHA-256 of `SPR/native-nitro/release/v1` followed by the 32-byte executable hash, seed commitment and custody digest. The custody digest is SHA-256 of the RFC 8785 canonical `custody` object from the committed receipt. The signed target binds both that record and its epoch. The checkpoint remains in force if every listed replica is unavailable. Wallets send only after a replica attests. Raising the floor retires earlier epochs for that wallet. A later policy can authorize a previous build at or above that floor. New installs use independently pinned minimum values. The SDK uses one verified target for up to 60 seconds. The signed policy must be current for attestation and use. Every certificate in the attestation path must remain valid while the SDK uses that target.
4. Encrypt the request to that boot's P-256 transport key. A decrypt approval binds the signer, network, release, boot transport key ID, ordered outputs, request ID and the ephemeral client response key. The enclave verifies the approval before deriving or opening note keys. Its signed response binds the operation, request digest and encrypted result. Before opening the reply, the SDK verifies the replica signature and rechecks the persisted checkpoint and session deadline. It checks recovered notes against their indexed commitments.

The SDK gives each operation's HTTP exchange 12 seconds within the caller's
deadline. A timed-out replica is discarded. On a transport failure, a stale
boot rejection or a server error, an unsigned key lookup can retry once with
fresh policy checks and attestation. Signed decrypt failures return to the
wallet. A new call binds a fresh approval to its selected boot.

The parent may replay a previously encrypted request to the same boot. Any result is still encrypted to the original signed response key. The service performs no chain writes and needs no replay database. The viewing and nullifier public keys are public lookup results. TLS protects ingress traffic in transit, while enclave-level encryption protects plaintext from ingress and the parent. See [AWS's attestation format and chain validation](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html).

The enclave accepts connections from the EC2 parent. It caps active vsock
connections at 64 for serving and four for provisioning or custody. Each
connection carries one HTTP/1 request. Headers have a 16 KiB buffer limit and
a three-second read deadline. The connection has a ten-second deadline that
covers writes to a slow parent. Operator HTTP exchanges have an eight-second
absolute deadline. Provisioning looks for a recipient for up to twenty seconds.
Successful provisioning drains its reply for up to five seconds before
closing the listener's remaining connections.
The serving router admits two attestation requests and 32 other requests
with a five-second request deadline. Each listener runs at most one Nitro
Security Module call on a blocking worker. The worker retains its permit
until the kernel call returns, including after a client disconnects.

## QuorumOS decision

Native Nitro uses AWS KMS for measured secret release, six recovery keys for threshold custody, and wallet release signers for promotion and rollback. Self-hosted QuorumOS provides a threshold boot ceremony and authenticated key forwarding across compatible environments. It adds a boot manifest, key forwarding and a common Quorum Key to the audit surface. Revisit it for custody across clouds. [QuorumOS key forwarding](https://github.com/tkhq/qos/blob/main/docs/key_forward.md)

See [operator runbook](deploy/nitro/README.md), [invariants](../tests/INVARIANTS.md) and [internal audit](../tests/AUDIT.md).
