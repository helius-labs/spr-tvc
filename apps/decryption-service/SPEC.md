# Decryption service

A sender can make a private transfer to a Solana address before its owner
registers a private wallet. The service derives keys for that address inside an
attested enclave. The recipient authorizes each decryption with an Ed25519
signature from the destination address.

The TypeScript integration is opt-in. See the [service README](README.md) for
the devnet endpoint, the [protocol](../../crates/protocol/README.md#decryption-service)
for wire encoding, and the [test invariants](../../TEST_INVARIANTS.md#decryption-service)
for coverage.

## Send

1. The sender confirms the recipient's Solana address. The protocol verifies
   control of that address when the recipient claims the transfer. The sender
   is responsible for choosing the right address.
2. The sending wallet checks the registry. If the recipient has a registered
   wallet, it uses the registered keys. To pay privately before registration,
   the sender explicitly opts in to the service and the wallet calls
   `PublicKeys(address)` on the verified release. It returns the address's
   X25519 viewing public key and nullifier public key. This operation requires
   no owner signature and rejects malformed, off-curve, and small-order
   Ed25519 addresses. Program-derived addresses cannot claim via this flow.
3. The wallet constructs a default-ring transfer. The output commitment binds
   the destination address and the service nullifier public key through
   `owner_hash`. The sender encrypts the output to the service viewing public
   key using its transaction or deposit envelope key. The destination address
   is the spending authority.

## Receive

1. The recipient opens the service identity with their Solana message signer.
   The wallet can send an empty `Decrypt` batch to get the service nullifier
   secret. This request requires the same authorization as a nonempty batch.
2. During sync, the wallet finds candidate outputs under the recipient's
   owner tag. For each batch it generates a fresh P-256 response key pair
   locally and keeps the private key. It builds the request with the
   ciphertexts, request ID, release pins, and response public key. The
   recipient signs the domain-separated Solana off-chain message for the
   network and this exact request digest. The recipient should approve only
   requests that their wallet built with its own response key.
3. The enclave opens the request under its Quorum key and checks its release
   bindings. It verifies the Ed25519 signature with the claimed signer
   before deriving that signer's service keys. It rejects more than 256
   items or a declared viewing key that differs from the derived key. It
   decrypts with the derived private key and encrypts the ordered results and
   the nullifier secret to the signed response public key. The service
   viewing private key stays in the enclave.
4. The wallet verifies the response's App Proof against the attested replica
   and the request, then opens the response with its one-time private key.
   The pool cipher has no authentication tag. The wallet decodes each
   candidate and accepts a UTXO only if its recomputed commitment equals the
   indexed output commitment. The enclave has no view of Solana state.
5. The owner signs a regular transfer to sweep the UTXOs to their own
   shielded wallet. The nullifier secret is used to build spend proofs. A
   spend also requires the owner's signing key. Use `transact` for the sweep.
   `merge_transact` requires the registered nullifier public key. If a sender
   fetched service keys just before registration, the recipient can still
   sync the service identity and sweep that transfer.

## Decrypt fields

Each v1 `DecryptItem` has six fields.

| Field | Role |
| --- | --- |
| `ciphertext` | Encrypted output from the index. |
| `viewing_public_key` | Declared recipient viewing key. The enclave compares it with the key derived for the verified signer. |
| `transaction_viewing_public_key` | Sender's ephemeral X25519 viewing public key from the transaction or ring-deposit envelope. Together with the recipient viewing secret it yields the shared secret for the cipher. |
| `salt` | 16-byte pool cipher salt. |
| `slot_index` | Transfer output slot, or zero for a ring deposit. |
| `label` | `Transfer` or `RingDeposit`. Selects the cipher domain. |

The enclave can derive the recipient viewing key from the signer, so
`viewing_public_key` is redundant for decryption. It catches a batch that
declares the wrong viewing identity. A matching declaration does not
authenticate the ciphertext. A mislabeled output is still opened with the
signer's key and its bytes must pass the wallet commitment check. Keep the
field in the shared v1 item. A future service-specific version could omit
it, with clients still using indexed viewing keys to select which service
key applies to historical outputs.

The sender's ephemeral viewing key is required input. Keep the v1 wire name
`transaction_viewing_public_key` to match SDK fields and signed requests.
Use **sender's ephemeral viewing key** when describing its role. The enclave
also has an ephemeral attestation key and the wallet has a one-time response
key. Those keys serve different protocols.

## Key custody and trust

- The service derives its master seed from the Quorum key and uses separate
  HKDF-SHA256 labels for the viewing and nullifier keys, with the raw address
  in both derivations. Replicas under the same Quorum key derive the same
  keys. See [wire encoding and derivation](../../crates/protocol/README.md#decryption-service).
- The wallet pins a signed release policy and verifies the Nitro Boot
  Proof, Quorum binding, and App Proofs. The gateway forwards encrypted
  request and response bodies. Its Helius API key authorizes gateway access.
  The Solana signature authorizes decryption.
- A replay still encrypts the reply to the signed response key. Anyone who
  holds its private key can read that reply. If the owner signs a request
  built with someone else's response key, that party receives the batch and
  the owner's service nullifier secret. The secret can link spends for
  outputs whose plaintext the party knows.
- Quorum operators and release authorities are the confidentiality trust
  root. Two of the three shares can reconstruct the Quorum key. Operators
  verify attestation and manifest approvals before provisioning a release.
  An approved enclave image can read the seed. Seed exposure reveals all
  transfers under that Quorum key. Spending still requires each owner's
  signature.
- The Quorum key backs existing outputs. If it is lost, the service cannot
  open them. Replacing it produces a new set of service keys. Retire public
  key lookup on the old application and retain its decrypt path while owners
  sweep old outputs. A compromised key exposes the old outputs even after
  replacement. While the service is offline, a wallet cannot use it to open
  new ciphertexts.

PDA authorization and anonymous recipient tags require separate protocol
support.
