# Decryption service specification

A private transfer can name a Solana address before its owner registers a
private wallet. The address controls spending. An attested enclave holds its
service viewing key, and the address must sign each request to open outputs.
Service calls are read-only. The wallet builds and submits the sweep transaction.

## Verify the enclave

The SDK checks the signed release policy for the selected network. The policy
pins the Quorum public key, manifest and executable digests, and allowed
operations. The SDK checks discovery against that policy.

The SDK sends a fresh challenge encrypted to the pinned Quorum key. It
checks the signed answer and verifies the replica's Turnkey Boot Proof. The
proof must chain to the pinned AWS Nitro root and match the expected PCR0–3.
PCR17 commits to the approved manifest digest and the replica's ephemeral
public key. The SDK verifies operation App Proofs against the same policy,
using the Boot Proof for the replica that signed each answer.

## Send and claim

1. **Send.** The wallet checks the registry for the destination address. With
   the sender's opt-in, it calls `PublicKeys(address)` for an unregistered
   recipient. The lookup is public. The enclave returns that address's service
   viewing and nullifier public keys. It accepts on-curve Ed25519 addresses
   and rejects malformed and small-order keys. Program-derived addresses
   cannot use this flow.
   The sender encrypts the output to the service viewing key. The output
   commitment binds the destination address and service nullifier public key
   through `owner_hash`.
2. **Authorize.** The recipient wallet finds candidate outputs under its
   owner tag. For each batch, it generates a fresh P-256 response key pair
   and retains the private half. The recipient signs a Solana off-chain
   message that binds the network, release, request ID, full ordered batch,
   and response public key. An empty batch uses the same authorization and
   returns the recipient's service nullifier secret.
3. **Decrypt.** The enclave opens the request under its Quorum key and
   checks the release. It verifies the Ed25519 signature before deriving
   service keys from the verified address. It rejects batches over 256 items
   and any declared recipient viewing key that differs from the derived
   key. It opens every item under that derived private key. A rejected item
   yields an error for the whole batch.
4. **Verify and sweep.** The enclave encrypts the ordered plaintexts and
   nullifier secret to the signed response key. Its App Proof binds the
   request and encrypted result. The SDK verifies the proof before opening
   the reply. The pool cipher has no authentication tag, so the SDK accepts
   a decoded note only when its recomputed commitment matches the indexed
   output. The recipient can claim these notes after registration. Use
   `transact` to sweep them with the owner's transaction signature.
   `merge_transact` requires the registered nullifier public key.

## Cipher inputs

| Input | Purpose |
| --- | --- |
| `ciphertext` | Pool ciphertext from the indexed output. |
| `viewing_public_key` | Declared recipient key. The enclave checks it for consistency with the key derived from the signer. |
| `transaction_viewing_public_key` | Sender's ephemeral X25519 key. The enclave combines it with the recipient viewing secret to derive the shared secret. |
| `salt` | 16-byte pool cipher salt. |
| `slot_index` | Transfer output index as a `u32`, or zero for a ring deposit. |
| `label` | `Transfer` or `RingDeposit`, each with a separate cipher domain. |

A matching recipient declaration carries no proof of the ciphertext's
origin. A foreign ciphertext relabeled with the recipient's key is still
opened under the recipient's key. The SDK's commitment check applies in both
cases.

## Key custody and trust

- The service derives a master seed from the Quorum key. Distinct HKDF-SHA256
  labels and the recipient address separate viewing and nullifier keys.
  Replicas and releases under the same Quorum key derive the same keys.
  The viewing private key stays inside the approved enclave during operation.
- The Solana signature authorizes decryption. A relay can see encrypted
  request sizes and timing. While the release serves a signed request, a
  replay can produce another reply to the same signed response key.
- Anyone holding the corresponding response private key can read the reply.
  Approve a request only if your wallet generated that key. Disclosure of
  the nullifier secret can link spends for outputs whose plaintext is known.
  Spending requires the owner's transaction signature.
- The release authorities and Quorum operators must approve trustworthy
  code. Two of the three devnet shares can reconstruct the Quorum key.
  An approved image can read that key, and key exposure compromises
  confidentiality for all outputs encrypted under it.
- Losing the Quorum key makes its outputs unreadable. Replacing it derives
  new service keys. Keep the original key available for decrypting existing
  outputs until owners sweep them.

See the [wire protocol](../../crates/protocol/README.md#decryption-service)
for encodings and derivation labels, and the
[test invariants](../../TEST_INVARIANTS.md#decryption-service) for coverage.
