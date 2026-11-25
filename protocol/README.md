# Decryption wire protocol v1

## Encoding

JSON rejects unknown and duplicate fields. Hashed objects use RFC 8785
canonical JSON (JCS). Binary fields use lowercase hex without `0x`, and
`u64` fields use canonical decimal strings. Solana addresses use base58.
The network is `devnet` or `mainnet`. P-256 public keys are 65-byte
uncompressed SEC1 points. P-256 signatures are 64-byte raw low-S `r || s`.
A viewing public key is `0x04 || u`, with a canonical 32-byte little-endian
X25519 coordinate `u`.

`H(domain, payload) = SHA256(domain || 0x00 || payload)`.

| Domain | Payload |
| --- | --- |
| `SPR_TVC_DECRYPTION_SERVICE_REQUEST_V1` | `JCS(request)` with `operation.signature` omitted |
| `SPR_TVC_RESULT_V1` | Encrypted result bytes |
| `SPR_TVC_RELEASE_POLICY_V1` | `JCS(policy)` |

## QOS request and reply envelopes

A QOS public key is `encryption_sec1[65] || signing_sec1[65]`. Each envelope
uses a fresh sender P-256 key pair and a random 12-byte nonce. The receiver
uses its encryption private key. In the frame below, `E` and `R` are the
uncompressed sender and receiver public keys. `X` is the 32-byte P-256 ECDH
x-coordinate.

```text
key = HMAC-SHA512(key = E || R || X, msg = "qos_encryption_hmac_message")[0..32]
aad = E || 0x41 || R || 0x41
frame = nonce[12] || E[65] || sealed_len:u32le || ciphertext || tag[16]
```

AES-256-GCM uses `key`, `nonce`, and `aad`. The Borsh length
`sealed_len` includes the tag. The request receiver is the pinned Quorum
key. The reply receiver is the client's one-time response key.

## Decryption service

`POST /v1/operations` takes `version`, `quorum_key_id`, `quorum_key_epoch`,
and `ciphertext`. Its envelope contains canonical JSON with `version`,
32-byte `request_id`, `target_release_id`, `target_manifest_digest`,
`target_executable_digest`, `quorum_key_id`, `quorum_key_epoch`,
`client_response_public_key` (P-256 SEC1), and `operation`.

| Operation | Result |
| --- | --- |
| `PublicKeys { address }` | `viewing_public_key` and `nullifier_public_key` (32 bytes for the nullifier key) |
| `Decrypt { signer, signature, items, grant? }` | `plaintexts` (one per item in order) and `nullifier_secret` (31 bytes). Any item count that fits in the encrypted body. |

The operation and its result each carry a `type` tag. `Decrypt` requires the
signer's 64-byte Ed25519 signature over a Solana off-chain message v0, format
0, with one signer. Its application domain is
`SHA256("TSPP/decryption-service/decrypt/v1")`.
The payload is `TSPP/decryption-service/decrypt/v1/<network>/<hex request digest>`.

An absent `grant` means `signer` is the owner. A present `grant` means `signer`
is the grantee. The owner signs it locally, over
`TSPP/decryption-service/view-grant/v1/<hex grant digest>`, where the digest is
`H(SPR_TVC_VIEW_GRANT_V1, JCS(grant))` without `signature`. The signed fields
are `owner`, `grantee`, `network`, `quorum_key_id`, `quorum_key_epoch`,
`not_before_ms`, and `expiry_ms`. The enclave accepts the grant while its
clock is inside `[not_before_ms, expiry_ms)` and that span is at most 30
minutes. A failed clock read denies the request. The grantee receives the
same `nullifier_secret` as the owner. The enclave stores no grants.

The response contains `version`, `request_id`, `encrypted_result`, and
`tvc_app_proof`. The App Proof carries `scheme`
(`SIGNATURE_SCHEME_EPHEMERAL_KEY_P256`), the replica's QOS `public_key`,
`proof_payload` (a JCS string), and `signature`. The replica's ephemeral
signing key signs the exact UTF-8 payload with P-256/SHA-256. The payload carries
`type = spr.tvc.decryption_service.v1`, `version`, `request_id`,
`request_digest`, `result_digest`, and `operation` (`ServicePublicKeys`
or `ServiceDecrypt`). The SDK verifies the signature, replica attestation,
and all bindings before opening the result. The HTTP request body and the
binary encrypted result are each limited to 10 MiB, the same cap as the
indexer. An empty indexer page of 1,000 50-byte recipient notes measures
675,814 bytes (`plaintext + 12 + 65 + 4 + 16`, then hex).
`protocol/fixtures/page-limit.json` records both lengths.

## Key derivation and SPR note cipher

The following derivations use HKDF-SHA256 with no salt. The address in
`info` is the raw 32-byte Ed25519 public key of the owner for `Decrypt`
(the signer, or the grant's `owner`) and the requested address for `PublicKeys`.

| Input key material | `info` | Output |
| --- | --- | --- |
| QOS Quorum master seed | `TSPP/decryption-service/seed/v1` | 32-byte service seed |
| Service seed | `TSPP/decryption-service/view_key/x25519/v1` followed by the address | 32-byte X25519 viewing secret, clamped by X25519 |
| Service seed | `TSPP/decryption-service/nf_key/v1` followed by the address | 31-byte nullifier secret |
| Nullifier secret | `TSPP/decryption-service/tx_key/v1` | 32-byte seed the wallet uses to derive local transaction viewing keys |

A decrypt item carries `ciphertext`, `ephemeral_viewing_public_key`, a
16-byte `salt`, `slot_index`, `label`, and `kdf`. The only mode is
`HkdfSha256Ctr`. A missing or unknown mode is rejected. The enclave derives the
recipient viewing key from the verified signer. SPR rejects an all-zero
X25519 shared secret and uses the following key schedule.

```text
ikm  = X25519_shared_secret || sender_tagged_public_key || recipient_tagged_public_key
info = "TSPP/hpke/" || cipher_domain || salt || slot:u32be
okm  = HKDF-SHA256(no salt, ikm, info, 44)
```

`Transfer` uses cipher domain `TSPP/tx` and the output slot as a `u32`.
`RingDeposit` uses `TSPP/ring_deposit` and requires slot zero. AES-256-CTR
uses the first 32 output bytes as its key, the last 12 as its nonce, and
starts with counter `nonce || 0x00000002`. See the
[pinned SPR implementation](https://github.com/helius-labs/zolana/blob/c5297afa13e8bfb6edadf6408304ef3fc2f8c676/sdk-libs/keypair/src/encryption.rs).

## Release policy and connection

The policy pins the release, network, security domain, manifest and
executable digests, Quorum key identity and public key, operations, and
byte limits. A threshold of distinct trusted release authorities signs the
policy digest with P-256. The client enforces the policy's validity window
and revocation floor. See the [trust and attestation flow](../decryption-service/SPEC.md#establish-trust-before-sending).

- `GET /v1/info` returns discovery fields that the SDK checks against the policy.
- `POST /v1/ping` takes `version` and `encrypted_challenge`. The decrypted
  JSON has `type = spr.tvc.qos_ping.v1`, `version`, and a random 32-byte
  `challenge`. The response contains `version` and an App Proof on the
  exact challenge JSON.
- `GET /health` reports process readiness.

## Fixtures

`just regenerate-protocol-fixtures` updates the shared byte vectors in
[`fixtures/`](fixtures) and their [SHA-256 manifest](fixtures/MANIFEST.json).
Rust and TypeScript check the committed bytes.
