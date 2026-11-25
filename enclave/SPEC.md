# Decryption service v1

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
   Startup refuses the envelope unless its manifest-set approvals meet the
   manifest threshold, pivot debug mode is off, and the pivot environment is
   empty. The process arguments must equal the launch arguments in that
   manifest. The service also checks its loaded Quorum key against the manifest. It reports
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

1. **Look up the recipient.** For a recipient without a registry record, the
   sender can call `PublicKeys(address)` on the verified service. Anyone can
   look up the service viewing and nullifier public keys. The enclave accepts
   on-curve Ed25519 addresses and rejects small-order keys. Program-derived
   addresses cannot authorize this flow.
2. **Encrypt and publish.** The sender uses its ephemeral X25519 viewing
   secret and the recipient's service viewing public key to encrypt the
   note's asset ID, amount, blinding, and optional ring and application data.
   The chain exposes the ciphertext, sender's ephemeral public key, cipher
   salt, output position, and note commitment. The owner tag exposes the
   recipient's Solana address. The commitment binds that address and service
   nullifier public key through `owner_hash`.
3. **Authorize the exact batch.** The recipient wallet uses the owner tag to
   find candidate outputs. It generates a fresh P-256 response key pair and
   keeps the private key. The signer of the batch is the owner, or a grantee
   named in a view grant the owner signed on a device. The grant lasts at
   most 30 minutes, is checked against the enclave clock, and is not stored.
   The signer signs a Solana off-chain message that binds the network, target
   release and Quorum identity, fresh request ID, ordered items, response
   public key, and, when present, the grant. The SDK seals the signed request
   to the pinned Quorum encryption key. An empty batch uses the same
   authorization to obtain the service nullifier secret. A grantee receives
   that secret too. The window does not erase a secret already returned.
   Spending a note still requires the owner's Solana signature.
4. **Open inside the enclave.** The enclave authenticates the envelope,
   checks that it targets the running release, and verifies the signer's
   Ed25519 signature. Without a grant, the signer address selects the
   recipient viewing secret. With a grant, the grant owner selects it. The
   enclave rejects a missing clock, a window outside 30 minutes, or a grant
   for another network or Quorum key. Each item's ephemeral viewing public key
   is the sender's X25519 input. There is no item cap. One signature covers
   one indexer page of 1,000 notes. An empty page, 50-byte ciphertexts and
   `u64::MAX` slots, measures 631,814 bytes after the 97-byte QOS frame and
   hex encoding. The service accepts 10 MiB, the same body cap as the indexer.
   The encrypted result uses the same ceiling. A larger body is
   rejected before any ciphertext is opened. Concurrent requests can multiply
   the cap by the number of connections the process accepts. There is no
   separate inflight limit. Any malformed item fails the entire batch.
5. **Return and verify.** The enclave seals the ordered plaintexts and the
   recipient's nullifier secret to the signed response public key. The
   replica signs an App Proof binding the request ID, operation, request
   digest, and encrypted result digest. The SDK verifies the proof before
   opening the reply. The SPR wallet decodes each candidate and recomputes
   its commitment before accepting it as a note.
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
  signature. A v1 signature does not expire. A replay only produces another
  reply to the original response key. The App
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
  two purposes. The viewing secret stays in the enclave. An authorized
  reply exports the nullifier secret, which can link spends for known notes
  if leaked. A view grant gives the grantee that secret for notes decrypted
  during the window. Spending a note still requires the owner's signature.
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
