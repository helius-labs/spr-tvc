# Native Nitro security specification

SPR senders can encrypt an output for a wallet that has no registry entry. The service derives the wallet's viewing and nullifier keys from a stable, network-specific seed and the owner's Solana address. See [the request and output specification](SPEC.md) for canonical messages, owner authorization, output handling and SDK commitment checks.

## Trust and custody

| Actor | Authority |
| --- | --- |
| Wallet owner | Signs a decrypt batch and the response public key. The matching response private key opens its reply. |
| Two note-share custodians | Each holds one independently generated 32-byte share. Both approve wrapping their share for a new measured target. A single share reveals no information about the XOR of the two independently random shares. |
| Release signers | At least two distinct pinned P-256 keys authorize a policy. Use two of three separately controlled KMS signing keys. Each signed target names an HTTPS route, release ID, executable SHA-256 and PCR0–PCR3. |
| EC2 parent and ingress | Can choose when and where to forward requests, and can deny service. See note ciphertexts, wrapped shares, TLS metadata, timings and sizes. Never receive note plaintext or a private key via the protocol. |
| AWS Nitro and KMS | Nitro isolates enclave memory and signs evidence. Each KMS key enforces its own measured-target and context restrictions. The two share accounts must have separate administrators and recovery access. |
| Wallet integration | Distributes pinned policy URL, network, security domain, note seed commitment, authority public keys, threshold and a minimum release sequence. Stores the highest accepted sequence and policy digest in durable atomic state. |

A release must pass **both** controls. The custodians can provision a measured target that wallets will refuse until the release signers authorize it. The release signers can authorize a target that remains unready until both shares are provisioned. Review the source, EIF and key policies before either approval. A malicious image approved by both controls can disclose the seed. A single permission holder must never control both custody accounts or the release-signing threshold.

## Startup

1. The EIF measures the application, network build, release ID, security domain and SHA-256 of each share. Each custodian publishes only the hash of their own share. The enclave computes the note seed as their XOR. Each share is stored under a different AWS account's KMS key. The image carries only the commitment.
2. At boot the enclave generates a temporary RSA-2048 recipient. It returns a Nitro attestation for that public key over the EC2-only vsock listener on port 44031. The parent calls KMS `Decrypt` with the evidence, wrapped share and exact context for each key. The policy requires PCR0–PCR3 from the approved target and the context binds purpose, network, security domain, release and share index.
3. Each KMS response contains CMS encrypted for the attested RSA key. The parent sends both CMS records in one frame. The frame is a two-byte big-endian length followed by the first record and the second record. Each must be at most 6,144 bytes. The enclave checks both decrypted shares are distinct, nonzero 32-byte values and each one matches its measured commitment before combining them. A failed request consumes neither share. The recipient is dropped after the first successful request. Bootstrap expires after two minutes and readiness requires success.
4. The enclave generates independent P-256 pairs for request encryption and response signing. It serves on vsock port 44030. The boot-specific transport key ID is the SHA-256 of its public pair. No boot key is persisted or used in note-key derivation.

The measured commitment also prevents the parent from injecting a different seed by encrypting its own shares for the public recipient. See [KMS recipient handling](https://docs.aws.amazon.com/kms/latest/developerguide/attested-calls.html) and [attestation conditions](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html).

## Wallet connection and operations

1. Fetch the policy from the independently configured URL with a 32 KiB body limit. Require the configured threshold of distinct low-S P-256 signatures over SHA-256 of the UTF-8 string `SPR/native-nitro/release-policy/v1` followed by RFC 8785 canonical policy JSON. Check the network, domain, seed commitment and allowed lifetime, then atomically record the accepted sequence and digest. A higher sequence can authorize an older image for deliberate rollback. Retrying the same sequence requires the identical digest. A new install must start at the application's trusted minimum sequence.
2. POST a random 32-byte nonce to one authorized target's `/v1/nitro/attestation`. The reply includes discovery and the AWS-signed COSE evidence for that same boot. The document signs the nonce, the SHA-256 of `SPR/native-nitro/discovery/v1` followed by canonical discovery, and the replica's response-signing public pair.
3. Verify the exact pinned AWS root, the current certificate path and usages, the ES384 COSE signature, the signed timestamp and nonce, PCR0–PCR3 and the discovery bindings. Verify both public pairs before use. The SDK computes the discovery release digest as SHA-256 of `SPR/native-nitro/release/v1`, the 32-byte approved executable hash and the pinned 32-byte seed commitment. The seed commitment is SHA-256 of `SPR/native-nitro/note-seed/v1` followed by the two measured share hashes in order. Discovery cannot supply its own trust anchors. The SDK uses one verified target for at most 60 seconds and never past the policy's expiration.
4. Encrypt the request to that boot's P-256 transport key. A decrypt approval binds the signer, network, release, boot transport key ID, ordered outputs, request ID and the ephemeral client response key. The enclave verifies the approval before deriving or opening note keys. Its signed response binds the operation, request digest and encrypted result. The SDK checks the signature against the attested replica key before decrypting. It checks recovered notes against their indexed commitments.

The parent may replay a previously encrypted request to the same boot. Any result is still encrypted to the original signed response key. The service performs no chain writes and needs no replay database. The viewing and nullifier public keys are public lookup results. TLS protects ingress traffic in transit, while enclave-level encryption protects plaintext from ingress and the parent. See [AWS's attestation format and chain validation](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html).

## QuorumOS decision

Native Nitro uses a smaller runtime for this service. AWS/KMS provides measured secret release, two independently administered share keys provide custody, and wallet release signers provide promotion and rollback authorization. Self-hosted QuorumOS can provide a threshold boot ceremony and authenticated key forwarding. It adds a boot manifest, key forwarding and a common Quorum Key to the audit surface. Revisit it if the custodian model requires a native hardware-share ceremony or quorum-governed forwarding across clouds. Preserve the independent note seed and distinct client release authority in either design. The hosted QOS build remains a separate deployment path. [QuorumOS key forwarding](https://github.com/tkhq/qos/blob/main/docs/key_forward.md)

See [operator runbook](deploy/nitro/README.md), [invariants](../tests/INVARIANTS.md) and [internal audit](../tests/AUDIT.md).
