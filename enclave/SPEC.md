# Decryption service v1

For the native Nitro deployment, see [its startup, custody and client-attestation
specification](NITRO.md). This document describes the shared Solana
authorization and decryption protocol and the Turnkey deployment's trust path.

This service lets a sender encrypt a Solana Privacy Rings (SPR) note for a
Solana address before its owner registers a shielded wallet. The owner
already controls an Ed25519 signing key. The enclave supplies a stable public
viewing key for that address and releases decrypted bytes only after the owner
signs the request.

## Establish trust before sending

1. **Approve a deployment.** The release tool compares the authenticated
   Turnkey deployment with the reviewed image digest, executable, launch
   arguments, and configured Quorum key. Operators approve the manifest and
   provision the Quorum key through Turnkey.
2. **Start the enclave.** Turnkey's Quorum OS (QOS) writes `/qos.manifest` inside
   the enclave. The JSON envelope contains the approved boot configuration
   (`manifest.version = "v2"` in the QOS schema) and its approval signatures.
   The service checks its loaded Quorum key against the manifest. It reports
   that public key, the canonical digest of the inner manifest, and the
   executable digest in `/v1/info`. The release tool verifies the live
   replica before writing a signed SDK release pin.
3. **Verify the endpoint.** The SDK checks the policy's authority signatures,
   network, and validity window, then matches discovery to the policy. For
   mainnet, the SDK independently pins the authority set, revocation floor,
   Quorum key, security domain, and maximum policy lifetime. It encrypts a
   fresh challenge to the approved Quorum key and verifies the replica's
   signature on the exact challenge to prove live access to that Quorum key.
4. **Authenticate the replica key.** The SDK verifies the Turnkey Boot Proof's
   COSE signature and certificate chain up to the pinned AWS Nitro root. It
   compares Nitro's PCR0–3 measurements with the pinned QOS identity and
   compares the manifest digest in the attested user data with the release
   policy. PCR17 must commit to that digest and the replica's ephemeral
   public key. An operation may reach a different replica, so the SDK
   verifies the Boot Proof for the key that signed each reply.

## Send, claim, and sweep

1. **Look up the recipient.** Use the registered wallet keys when present.
   After a confirmed registry miss, the wallet checks that the payment RPC’s
   Solana genesis hash matches the service network before requesting
   `PublicKeys(address)`. Anyone can request the service viewing and nullifier
   public keys. The enclave accepts on-curve Ed25519 addresses and rejects
   small-order keys and program-derived addresses.
2. **Encrypt and publish.** The sender uses its ephemeral X25519 viewing
   secret and the recipient's service viewing public key to encrypt the
   note's asset ID, amount, blinding, and optional ring and application data.
   The chain exposes the ciphertext, sender's ephemeral public key, cipher
   salt, output position, and note commitment. The owner tag exposes the
   recipient's Solana address. The commitment binds that address and service
   nullifier public key through `owner_hash`.
3. **Authorize the exact batch.** The recipient wallet uses the owner tag to
   find candidate outputs. It generates a fresh P-256 response key pair and
   keeps the private key. The owner signs a Solana off-chain message that
   binds the network, target release and Quorum identity, fresh request ID,
   ordered items, and response public key. The SDK seals the signed request
   to the pinned Quorum encryption key. An empty batch uses the same
   authorization to obtain the service nullifier secret.
4. **Open inside the enclave.** The enclave authenticates the envelope,
   checks that it targets the running release, and verifies the owner's
   Ed25519 signature. The verified signer address alone selects the recipient
   viewing secret for every item. Each item's ephemeral viewing public key
   is the sender's X25519 input. The enclave accepts up to 256 items. Any
   malformed item fails the entire batch.
5. **Return and verify.** The enclave seals the ordered plaintexts and the
   recipient's nullifier secret to the signed response public key. It writes
   canonical JSON directly into a fixed-capacity buffer and wipes that buffer
   after encryption. The replica signs an App Proof binding the request ID,
   operation, request digest, and encrypted result digest. The SDK verifies
   the proof before opening the reply. It binds the handle to the owner and verifies the
   nullifier secret against the discovered public key. Later replies must
   carry the same secret and one plaintext of the expected length per item.
   The SPR wallet recomputes each candidate's commitment before accepting it.
6. **Sweep.** The recipient wallet derives transaction viewing keys locally
   from the service nullifier secret and can sweep the notes into its
   shielded wallet using `transact`. `merge_transact` requires the registered
   nullifier public key. The wallet supplies a witness to its configured
   prover and the owner signs the Solana transaction.

## What protects the data

- **Note on chain.** X25519 gives the sender and the enclave a shared secret.
  SPR uses HKDF-SHA256 to derive an AES-256-CTR key and nonce from that secret,
  both public keys, the cipher domain, salt, and slot. Confidentiality
  requires private X25519 keys and a distinct key/nonce pair for each
  plaintext. CTR has no authentication tag. Modified or wrong-recipient
  ciphertext can yield bytes, so the wallet checks the decoded note against
  its published commitment. Encrypted memos sit outside the commitment and
  remain untrusted.
- **Wallet to enclave.** The QOS envelope derives an AES-256-GCM key from
  ephemeral P-256 ECDH. GCM authenticates the ciphertext and both public keys.
  Anyone can encrypt to the Quorum public key, so the enclave separately
  verifies the owner's signature. The relay sees the request version, Quorum
  key ID and epoch, and the reply's App Proof, as well as sizes and timing.
  The indexer sees the wallet's queries.
- **Enclave to wallet.** The QOS envelope encrypts to the one-time response
  key. A relay cannot change that key without invalidating the owner's
  signature. A replay can elicit another reply to the original key. The App
  Proof authenticates the reply, and the response private key opens it.
- **Wallet to prover.** The configured prover receives the transaction
  witness, including the service nullifier secret when proving a spend of a
  service note. The wallet relies on the prover to protect that data.

Deposits, withdrawals, and timing can reveal additional information about
transfers.

## Key custody and trust

- **Owner Ed25519 key.** The wallet signer, such as Turnkey in the example,
  authorizes decrypt batches and separately signs Solana transactions. The
  wallet must generate and retain the response private key for its approval.
- **Quorum key.** Approved replicas under the same Quorum seed derive the same
  keys across releases. HKDF binds each key to its address and separates the
  two purposes. The viewing secret stays in the enclave. The owner-authorized
  reply exports the nullifier secret, which can link spends for known notes
  if leaked.
- **Release and recovery.** Confidentiality depends on the approved image,
  Nitro isolation, and Quorum custody. An approved image can read the Quorum
  seed. Anyone who obtains it can decrypt recorded requests and derive
  every service viewing secret under it to decrypt historical notes.
  Losing the seed makes unswept notes unreadable. Rotation changes the
  service keys, so recipients need the previous service until they sweep.
  Cached public keys let senders create outputs without a service call,
  so exposure limits belong at admission.

[Wire encodings and derivations](../protocol/README.md) ·
[Test invariants](../tests/README.md) · [Release runbook](../xtask/README.md)
