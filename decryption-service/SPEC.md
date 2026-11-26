# Decryption service v1

A sender can encrypt an SPR note to a Solana address before that address has a shielded wallet. The owner already has an Ed25519 key. The enclave holds a stable viewing key for the address and returns plaintext only after that owner, or a grantee they named, signs the request.

## Establish trust before sending

An operator does not pin a URL. The release tool compares a Turnkey deployment with the reviewed image digest, the executable, the launch arguments, and the Quorum key. Operators approve that manifest and provision the Quorum key in Turnkey.

On boot, Quorum OS writes `/qos.manifest`. The envelope is QOS schema `manifest.version = "v2"` plus the approval signatures. The process refuses to start unless those approvals meet the manifest threshold, pivot debug mode is off, and the pivot environment is empty. Its arguments must be the launch arguments in the manifest, and the Quorum key it loaded must be the key the manifest names. `/v1/info` then reports that public key, the digest of the inner manifest, and the executable digest. The release tool checks this live replica before it writes a signed SDK pin.

The SDK checks the pin before it uses the endpoint. It verifies the authority signatures, the network, and the validity window, and it matches discovery to the policy. On mainnet the authority set, the revocation floor, the Quorum key, the security domain, and the maximum policy lifetime are pinned in the SDK. A policy cannot choose them. The SDK encrypts a fresh challenge to the approved Quorum key and checks the replica's signature over that exact challenge. That is how it knows the replica can use the key.

The replica's signing key is a separate check. The SDK verifies the Boot Proof's COSE signature and the certificate chain up to the pinned AWS Nitro root. PCR0–3 must match the pinned QOS identity. The manifest digest in the attested user data must match the release policy, and PCR17 must commit to that digest and to the replica's ephemeral public key. A later call may reach a different replica, so the SDK repeats the Boot Proof check for the key that signed each reply.

## Send, claim, and sweep

A sender whose recipient has no registry record calls `PublicKeys(address)` on the service it just verified. The call is public. It returns the service viewing key and the nullifier public key. The enclave accepts on-curve Ed25519 addresses and rejects small-order keys. A program-derived address cannot authorize a decrypt.

The sender encrypts the note with an ephemeral X25519 secret and the recipient's service viewing key. The plaintext is the asset id, the amount, the blinding, and any ring or application data. The chain publishes the ciphertext, the sender's ephemeral public key, the salt, the output position, and the note commitment. The owner tag is the recipient's Solana address. The commitment binds that address and the service nullifier public key through `owner_hash`.

The recipient wallet finds candidate outputs from the owner tag. It generates a fresh P-256 response key and keeps the private half. The signer is the owner, or a grantee named in a view grant the owner signed on a device. A grant lasts at most 30 minutes, is checked against the enclave clock, and is not stored. The signature is a Solana off-chain message over the network, the target release and Quorum identity, a fresh request id, the ordered items, the response public key, and the grant when there is one. The SDK seals that signed request to the pinned Quorum encryption key.

An empty batch is the same authorization, used to fetch the nullifier secret. A grantee receives that secret too. Ending the grant does not wipe a secret already returned. Spending a note still takes the owner's Solana signature.

Inside the enclave the envelope is authenticated, checked against the running release, and the Ed25519 signature is verified. With no grant, the signer address selects the viewing secret. With a grant, the grant's owner selects it. A missing clock, a window longer than 30 minutes, or a grant for another network or Quorum key is rejected. Each item names a key schedule. The only schedule is `HkdfSha256Ctr`: HKDF-SHA256 and AES-256-CTR. The item's ephemeral key is the sender's X25519 public key. One signature covers an indexer page. There is no item cap and no separate in-flight limit, so each accepted connection can carry its own 10 MiB body, and the encrypted result uses the same ceiling. A larger body is rejected before any ciphertext is opened. One bad item fails the batch.

The enclave seals the ordered plaintexts and the nullifier secret to the signed response key. The replica signs an App Proof over the request id, the operation, the request digest, and the encrypted-result digest. The SDK checks that proof before it opens the reply. The wallet decodes each candidate and recomputes the commitment before it accepts the note.

To sweep, the wallet derives transaction viewing keys from the nullifier secret and moves the notes into its shielded wallet with `transact`. `merge_transact` needs the registered nullifier public key. The wallet gives the witness to its prover. For a service note that witness includes the nullifier secret. The owner signs the Solana transaction.

## What protects the data

The note on chain is X25519 between the sender and the enclave. SPR runs HKDF-SHA256 over that shared secret, both public keys, the cipher domain, the salt, and the slot, and uses the output as an AES-256-CTR key and nonce. Confidentiality needs the X25519 private keys and a fresh key and nonce for every plaintext. CTR does not authenticate. A modified ciphertext, or one meant for someone else, can still decode to bytes, so the wallet checks the decoded note against the published commitment. Encrypted memos sit outside that commitment and are not trusted.

The request is a QOS envelope. Its AES-256-GCM key comes from ephemeral P-256 ECDH, and GCM covers the ciphertext and both public keys. Anyone can encrypt to the Quorum public key, which is why the enclave still checks the owner's signature. A relay sees the request version, the Quorum key id and epoch, the reply's App Proof, and the sizes and timing. The indexer sees the wallet's queries.

The reply is a QOS envelope to the one-time response key. A relay cannot swap that key without breaking the owner's signature. A v1 signature does not expire. Replaying the request only produces another ciphertext for the original response key. The App Proof authenticates the reply. The response private key opens it.

The prover sees the transaction witness, and for a service note that includes the nullifier secret. The wallet is trusting the prover with it.

Deposits, withdrawals, and timing reveal more than the ciphertext does.

## Key custody and trust

The owner's Ed25519 key authorizes decrypt batches and, separately, Solana transactions. In the example that key is Turnkey. The wallet creates the response key for its own approval and has to keep the private half.

Replicas approved under the same Quorum seed derive the same service keys across releases. HKDF binds each key to the address and keeps the viewing secret and the nullifier secret apart. The viewing secret stays in the enclave. An authorized reply exports the nullifier secret. If that secret leaks, spends of known notes can be linked. A view grant hands the grantee the same secret for notes opened during the window. Spending still requires the owner's signature.

Confidentiality is the approved image, Nitro isolation, and custody of the Quorum seed. An approved image can read the seed. Whoever has the seed can open recorded requests and derive every service viewing key under it, which opens historical notes. Losing the seed makes notes that were never swept unreadable. Rotation changes the service keys, so recipients need the previous service until they sweep. Senders can cache the public keys and create outputs without calling the service, so a limit on how much can be sent belongs at admission.

[Wire encodings and derivations](../wire/README.md) · [Test invariants](../tests/README.md) · [Release runbook](../xtask/README.md)
