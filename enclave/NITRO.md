# Native Nitro security specification

SPR senders can encrypt an output for a wallet that has no registry entry. The service derives the wallet's viewing and nullifier keys from a stable, network-specific seed and the owner's Solana address. See [the request and output specification](SPEC.md) for canonical messages, owner authorization, output handling and SDK commitment checks.

## Trust and custody

| Actor | Authority |
| --- | --- |
| Wallet owner | Signs a decrypt batch and the response public key. The matching response private key opens its reply. |
| Six note-share custodians | Each holds the recovery key for one Shamir share. Any three can commission a measured target or rotate custody. Recovering the seed with fewer than three shares would require breaking the public commitments. |
| Release signers | At least two distinct pinned P-256 keys authorize a policy. Use two of three separately controlled KMS signing keys. Each signed target names an HTTPS route, release ID, executable SHA-256 and PCR0–PCR3. |
| EC2 parent and ingress | Can choose when and where to forward requests, and can deny service. See note ciphertexts, wrapped shares, TLS metadata, timings and sizes. Never receive note plaintext or a private key via the protocol. |
| AWS Nitro and KMS | Nitro isolates enclave memory and signs evidence. Each KMS key enforces its own measured-target and context restrictions. The two share accounts must have separate administrators and recovery access. |
| Wallet integration | Distributes pinned policy URL, network, security domain, note seed commitment, authority public keys, threshold, minimum release sequence and minimum custody epoch. Stores the highest accepted sequence, policy digest and custody floor in durable atomic state. |

A release must pass **both** controls. The custodians can provision a measured target that wallets will refuse until the release signers authorize it. The release signers can authorize a target that remains unready until three valid shares are provisioned. Review the source, EIF and key policies before either approval. A malicious image approved by both controls can disclose the seed. Each custody account has independent administration and recovery access. No principal should reach the custody or release-signing threshold.

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
epoch. Qualify one exact record and use it consistently.

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

## Wallet connection and operations

1. Fetch the policy from the independently configured URL with a 32 KiB body limit. Require the configured threshold of distinct low-S P-256 signatures over SHA-256 of the UTF-8 string `SPR/native-nitro/release-policy/v1` followed by RFC 8785 canonical policy JSON. Check the network, domain, seed commitment and allowed lifetime, then atomically record the sequence, digest and custody floor. Raising the floor retires earlier epochs for that wallet, including against a higher-sequence signed policy. A deliberate rollback can authorize a previously approved target at or above the recorded floor. New installs use independently pinned minimum values.
2. POST a random 32-byte nonce to one authorized target's `/v1/nitro/attestation`. The reply includes discovery and the AWS-signed COSE evidence for that same boot. The document signs the nonce, the SHA-256 of `SPR/native-nitro/discovery/v1` followed by canonical discovery, and the replica's response-signing public pair.
3. Verify the exact pinned AWS root, the current certificate path and usages, the ES384 COSE signature, the signed timestamp and nonce, PCR0–PCR3 and the discovery bindings. Verify both public pairs before use. The SDK computes the discovery release digest as SHA-256 of `SPR/native-nitro/release/v1`, the 32-byte approved executable hash and the pinned 32-byte seed commitment. The signed target must name the attested custody epoch. Discovery cannot supply its own trust anchors. The SDK uses one verified target for at most 60 seconds and never past the policy's expiration.
4. Encrypt the request to that boot's P-256 transport key. A decrypt approval binds the signer, network, release, boot transport key ID, ordered outputs, request ID and the ephemeral client response key. The enclave verifies the approval before deriving or opening note keys. Its signed response binds the operation, request digest and encrypted result. The SDK checks the signature against the attested replica key before decrypting. It checks recovered notes against their indexed commitments.

The parent may replay a previously encrypted request to the same boot. Any result is still encrypted to the original signed response key. The service performs no chain writes and needs no replay database. The viewing and nullifier public keys are public lookup results. TLS protects ingress traffic in transit, while enclave-level encryption protects plaintext from ingress and the parent. See [AWS's attestation format and chain validation](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html).

## QuorumOS decision

Native Nitro uses a smaller runtime for this service. AWS/KMS provides measured secret release, two independently administered share keys provide custody, and wallet release signers provide promotion and rollback authorization. Self-hosted QuorumOS can provide a threshold boot ceremony and authenticated key forwarding. It adds a boot manifest, key forwarding and a common Quorum Key to the audit surface. Revisit it if the custodian model requires a native hardware-share ceremony or quorum-governed forwarding across clouds. Preserve the independent note seed and distinct client release authority in either design. The hosted QOS build remains a separate deployment path. [QuorumOS key forwarding](https://github.com/tkhq/qos/blob/main/docs/key_forward.md)

See [operator runbook](deploy/nitro/README.md), [invariants](../tests/INVARIANTS.md) and [internal audit](../tests/AUDIT.md).
