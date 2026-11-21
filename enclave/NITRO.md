# Native Nitro security specification

SPR senders can encrypt an output for a wallet that has no registry entry. The service derives the wallet's viewing and nullifier keys from a stable, network-specific seed and the owner's Solana address. See [the request and output specification](SPEC.md) for canonical messages, owner authorization, output handling and SDK commitment checks.

## Trust and custody

| Actor | Authority |
| --- | --- |
| Wallet owner | Signs a decrypt batch and the response public key. The matching response private key opens its reply. |
| Six note-share custodians | Each controls one sealed RSA recovery key in its own AWS account. All six prove recovery before a custody epoch is committed. Three shares can then commission an approved target or rotate custody. |
| Custody approval signers | Two of three pinned KMS keys approve the custody record or authorize release of shares to one measured target. The custody ledger admits one record per epoch. |
| Release signers | At least two distinct pinned P-256 keys authorize a policy. Use two of three separately controlled KMS signing keys. Each signed target names an HTTPS route, release ID, executable SHA-256 and PCR0–PCR3. |
| EC2 parent and ingress | Can choose when and where to forward requests, and can deny service. See note ciphertexts, wrapped shares, TLS metadata, timings and sizes. Never receive note plaintext or a private key via the protocol. |
| AWS Nitro, KMS and S3 | Nitro isolates enclave memory and signs evidence. KMS enforces key policies. S3 serializes conditional creation of custody records in a separately administered bucket. |
| Wallet integration | Distributes pinned policy URL, network, security domain, note seed commitment, authority public keys, threshold, minimum release sequence and minimum custody epoch. Stores the highest accepted sequence, policy digest and custody floor in durable atomic state. |

Commissioning requires two approvals of the exact target and three custodian shares. Wallets separately require a signed release policy and fresh attestation. A malicious enclave with three shares can disclose the seed even if wallets refuse to connect. Review the source and the measured artifact before approving share release. Account administration and role assumption must preserve the independence of custodians and approval signers.

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
recovery keys and its exact predecessor. All six custodians attest that their
sealed key can open its share. A conditional S3 write commits one record for
the epoch. Signers and custodians fetch that canonical record when authorizing
and wrapping for a target.

Custodians verify the quorum-approved build and destination and compare the
installed KMS policies to the approved role, context and measurements before
opening a share. A custodian workstation temporarily sees its one share.
KMS rewraps it for the target. The host sees ciphertext during this flow.

A serving EIF measures its network, release, security domain and current
custody record. Both serving and rotation use the same bootstrap:

1. The enclave creates a temporary RSA-2048 recipient and attests its public
   key on vsock port 44031. The parent calls KMS with that evidence and each
   wrapped share. A sealed key requires PCR0–PCR3 and exact context for
   network, security domain, release, custody epoch and share index.
2. KMS encrypts its response for that temporary recipient. The parent sends up
   to six CMS records, each prefixed by a two-byte big-endian length and
   limited to 6,144 bytes. The enclave counts three distinct committed shares
   from the measured epoch and verifies the recovered seed against the stable
   commitment. Unavailable keys, invalid shares and duplicates contribute no
   share. Invalid framing fails the batch and another request can retry.
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
previous published digest. The publisher verifies the new policy, checks its
predecessor and attests all activation targets. S3 accepts the change only if
its ETag still matches the checked predecessor. The encrypted note service
and ingress have no publication permission.

The wallet's trust bundle pins the S3 bucket, AWS owner and region. The wallet
reads the canonical policy directly from S3 without caching or redirects. A
new or restored wallet depends on that publication for freshness. S3 and its
publisher are trusted to serve the current policy. Release signatures and
Nitro evidence separately authorize each replica.

## Wallet connection and operations

1. Fetch the canonical policy with a 32 KiB body limit. Require the configured threshold of distinct low-S P-256 signatures over the policy digest. Check the network, domain, seed commitment and allowed lifetime. An `activate` policy lists eligible replicas. A `revoke` policy has an empty target list and commits its sequence, digest and custody floor immediately, returning `ReleasePolicyRevoked`.
2. POST a random 32-byte nonce to one authorized target's `/v1/nitro/attestation`. The reply includes discovery and the AWS-signed COSE evidence for that same boot. The document signs the nonce, the SHA-256 of `SPR/native-nitro/discovery/v1` followed by canonical discovery, and the replica's response-signing public pair.
3. Verify the exact pinned AWS root, the current certificate path and usages, the ES384 COSE signature, the signed timestamp and nonce, PCR0–PCR3 and the discovery bindings. Verify both public pairs before use. The SDK computes the discovery release digest as SHA-256 of `SPR/native-nitro/release/v1`, the 32-byte approved executable hash and the pinned 32-byte seed commitment. The signed target must name the attested custody epoch. After a replica passes verification, atomically persist the new sequence, digest and floor before using it. Raising the floor retires earlier epochs for that wallet. A later policy can authorize a previous build at or above that floor. New installs use independently pinned minimum values. The SDK uses one verified target for at most 60 seconds and never past the policy's expiration.
4. Encrypt the request to that boot's P-256 transport key. A decrypt approval binds the signer, network, release, boot transport key ID, ordered outputs, request ID and the ephemeral client response key. The enclave verifies the approval before deriving or opening note keys. Its signed response binds the operation, request digest and encrypted result. The SDK checks the signature against the attested replica key before decrypting. It checks recovered notes against their indexed commitments.

The parent may replay a previously encrypted request to the same boot. Any result is still encrypted to the original signed response key. The service performs no chain writes and needs no replay database. The viewing and nullifier public keys are public lookup results. TLS protects ingress traffic in transit, while enclave-level encryption protects plaintext from ingress and the parent. See [AWS's attestation format and chain validation](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html).

Each serving replica admits two HTTP attestation requests and 32 requests to
other routes. Request middleware sets a five-second deadline before reading
the body. The Nitro Security Module call runs on a separate blocking worker
with one call in flight. The worker retains its permit until the kernel call
returns, including after the client disconnects. Ingress also limits open
connections and applies admission control before forwarding to vsock.

## QuorumOS decision

Native Nitro uses AWS KMS for measured secret release, six recovery keys for threshold custody, and wallet release signers for promotion and rollback. Self-hosted QuorumOS provides a threshold boot ceremony and authenticated key forwarding across compatible environments. It adds a boot manifest, key forwarding and a common Quorum Key to the audit surface. Revisit it for custody across clouds. [QuorumOS key forwarding](https://github.com/tkhq/qos/blob/main/docs/key_forward.md)

See [operator runbook](deploy/nitro/README.md), [invariants](../tests/INVARIANTS.md) and [internal audit](../tests/AUDIT.md).
