# Decryption wire protocol

Version 2 of the wire protocol uses `/v2` routes. The Rust and [TypeScript](../sdk/src/protocol.ts)
implementations share the [conformance fixtures](#fixtures).

## Encoding

JSON inputs reject unknown and duplicate fields. Digested objects use
RFC 8785 canonical JSON (JCS). Binary fields are lowercase hex without
`0x` unless stated otherwise. A `u64` is a canonical decimal string. P-256
public keys are 65-byte uncompressed SEC1 and P-256 signatures are 64-byte
raw low-S `r || s`. Viewing public keys are 33-byte tagged X25519 keys,
`0x04 || u` with a canonical little-endian `u`. Solana addresses are
base58. The network is `devnet` or `mainnet`.

`H(domain, payload) = SHA256(domain || 0x00 || payload)`.

| Domain | Payload |
| --- | --- |
| `SPR_TVC_DECRYPTION_SERVICE_REQUEST_V2` | `JCS(request)` with `operation.signature` omitted |
| `SPR_TVC_RESULT_V2` | Encrypted result bytes |
| `SPR_TVC_RELEASE_POLICY_V2` | `JCS(policy)` |

## Envelope

The QOS P-256 public key pair is
`encryption_sec1[65] || signing_sec1[65]`. An envelope uses AES-256-GCM
with `HMAC-SHA512(key = ephemeral_pub || receiver_pub || ECDH_x, msg =
"qos_encryption_hmac_message")[0..32]` as its key. The AAD is
`ephemeral_pub || 0x41 || receiver_pub || 0x41`. Borsh encodes the frame
as `nonce[12] || ephemeral_pub[65] || encrypted_message_len:u32le ||
ciphertext || tag[16]`. The length includes the authentication tag.

## Decryption service

`POST /v2/operations` takes an `EncryptedRequest` with `version`,
`quorum_key_id`, `quorum_key_epoch`, and `ciphertext`. Its plaintext is a
`ServiceRequest` with `version`, a fresh 32-byte `request_id`,
`target_release_id`, `target_manifest_digest`, `target_executable_digest`,
`quorum_key_id`, `quorum_key_epoch`, `client_response_public_key` (one-time
uncompressed P-256), and `operation`.

The `EncryptedResponse` echoes the request ID and contains the encrypted
result and an App Proof. The replica's Ephemeral signing subkey signs the
exact UTF-8 proof payload with P-256/SHA-256. The payload binds the type
`spr.tvc.decryption_service.v2`, version, request ID, request and result
digests, and operation (`ServicePublicKeys` or `ServiceDecrypt`). Verify
the proof before opening the reply.
The HTTP request body and encrypted result each have a 262,144-byte limit.
Invalid operations return `InvalidRequest`.

| Operation | Returns |
| --- | --- |
| `PublicKeys { address }` | The address's service viewing and nullifier public keys. |
| `Decrypt { signer, signature, items }` | One plaintext per item, in order, and the nullifier secret. `items` may be empty. |

The master seed is
`HKDF-Expand(HKDF-Extract(∅, quorum master seed), "TSPP/decryption-service/seed/v1", 32)`,
so it is the same in every release and replica under the Quorum key, and
clients name it by the Quorum public key the release policy pins. It is as
durable as the Quorum key's shares.

Service keys are HKDF-SHA256 over the master seed with an empty salt, one
Expand per key: info `TSPP/decryption-service/view_key/x25519/v1 || address`
for the 32-byte viewing secret, which is then clamped, and
`TSPP/decryption-service/nf_key/v1 || address` for the 31-byte nullifier
secret. `address` is the 32 raw bytes of an on-curve Ed25519 address. The
service rejects small-order keys.

`Decrypt` names the base58 `signer` and carries the signer's 64-byte Ed25519
`signature` in lowercase hex, verified strictly, over a Solana off-chain message v0 (format 0,
one signer) whose application domain is
`SHA-256("TSPP/decryption-service/decrypt/v2")` and whose payload is
`TSPP/decryption-service/decrypt/v2/<network>/<hex of the request digest>`.
The digest binds the items, release pins, request ID, and one-time response
public key. The recipient client generates that key pair before asking the
owner to sign. The reply is encrypted to the signed public key, including
on replay. Reading it requires the corresponding private key.

`Decrypt` accepts up to 256 items. The verified signer determines the service
viewing key. Each item's `ephemeral_viewing_public_key` is the sender's
X25519 public key used to derive the shared secret.
The pool cipher is unauthenticated. The client keeps a decoded UTXO only when
its recomputed commitment equals the indexed output commitment.

When sweeping service outputs, the TypeScript wallet derives its own
transaction-key seed from the service nullifier secret via HKDF-SHA256 with
empty salt and info `TSPP/decryption-service/tx_key/v1`. The service viewing
private key remains in the enclave. See the
[send and receive flow](../enclave/SPEC.md).

## Release policy

A release policy names the release ID, network, security domain, accepted manifest and executable
digests, the Quorum key id, epoch and public key, the allowed operations, and
the request and response size limits. Release authorities sign
`H(SPR_TVC_RELEASE_POLICY_V2, JCS(policy))` with P-256; a client accepts
the policy only for the network it expects (`NetworkMismatch` otherwise) and
at a positive integer threshold of distinct authority keys. Unknown and
repeated signer IDs do not count. The SDK obtains the authority keys and
policy together from its release pin.

The trust material a client pins is the policy, the authority public keys,
and the QOS identity PCRs. Before its first operation, the client in
`@heliuslabs/spr-decryption-service` verifies the policy, binds every security
field of `GET /v2/info` to it, including the network, completes the
Quorum-encrypted `POST /v2/ping`, and verifies the Nitro Boot Proof against
the PCRs and the accepted manifest digests. The client verifies the signing
replica's attestation for each operation reply. `/health`
reports process readiness.

## Fixtures

`fixtures/` is generated by the conformance tests and hashed in
`fixtures/MANIFEST.json`. The Rust and TypeScript implementations must
produce these bytes. `just regenerate-protocol-fixtures` rewrites them; review
fixture and manifest diffs together, since the TypeScript suite reads the
committed files.
