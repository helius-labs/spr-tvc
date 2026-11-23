# Draft: time-bound view access

This draft adds one operation, `GrantView`, to the decryption service in
[SPEC.md](../SPEC.md). It does not change that specification. An
implementation pull request updates `SPEC.md`, the enclave, the TypeScript
SDK, and the Rust wallet together.

The enclave stores no grants. A grant is an owner signature the grantee
presents on each `Decrypt`. Any replica that holds the note seed accepts the
same grant until it expires, including after a reboot.

## Roles

The owner is the Solana address whose notes the enclave can open. The grantee
is a different Solana address. Both are canonical Ed25519 keys: a non-identity
point in the prime-order subgroup, with the canonical encoding. The grantee
and the owner are different addresses.

A grant names the network, the owner, the grantee, and one absolute expiry.
It carries no note keys. After the expiry, a grantee decrypt fails. Plaintexts
the grantee already received stay with the grantee.

## Two deadlines

`Decrypt` keeps its approval deadline. The SDK still sets `expires_at_ms`
within 60 seconds and within the verified session. The enclave still accepts
that deadline up to 120 seconds ahead of its clock.

The grant expiry is a second timestamp, `grant_expires_at_ms`. It is a Unix
time in milliseconds, encoded as a canonical decimal string like every other
`u64` on this wire. `MAX_GRANT_MS` is 30 days, 2,592,000,000 milliseconds.
`GrantView` accepts an expiry strictly after the enclave clock and at most
`MAX_GRANT_MS` past that clock. `Decrypt` accepts the grant only while the
enclave clock is strictly before that expiry. The grant expiry has no extra
skew allowance. Both checks use the same clock as the approval deadline: the
Nitro Secure Module on native Nitro, and the system clock on the QOS and
loopback implementations. A failed clock read denies the operation.

## Grant message

The owner signs a Solana off-chain message v0 with one signer, using the same
construction as the decrypt approval in [the wire protocol](../../protocol/README.md).
The signer is the owner. The label is `TSPP/decryption-service/grant-view/v1`.
The payload is

```text
TSPP/decryption-service/grant-view/v1/{network}/{grantee}/{grant_expires_at_ms}
```

`network` is `devnet` or `mainnet`. `grantee` is the base58 address. This
signature is the grant. It is independent of the request id, the response
key, and the release. The enclave verifies it again on every grantee decrypt
and does not treat an earlier `GrantView` call as permission.

## `GrantView`

`GrantView` is the third advertised operation. `/v1/info` lists
`supported_operations` in this order:

```text
["ServicePublicKeys","ServiceDecrypt","ServiceGrantView"]
```

Every client that compares that list uses the same order. A wallet that never
grants access still has to accept this list, or payment lookup fails against
the upgraded service. An old wallet that requires the two-operation list
refuses the upgraded service. The enclave and those clients ship in one
release.

The operation fields are:

| Field | Meaning |
| --- | --- |
| `signer` | The owner, base58. |
| `grantee` | The address receiving view access, base58. |
| `grant_expires_at_ms` | The grant expiry. |
| `grant_signature` | The owner's 64-byte Ed25519 signature over the grant message, lowercase hex. |
| `expires_at_ms` | The approval deadline for this request. |
| `signature` | The owner's signature over this request's digest. The digest omits `signature` and covers every other field, including `grant_signature`. |

The request signature uses the existing decrypt approval message and label.
The operation type is already inside the request digest.

The enclave checks the release binding, both signatures, the grantee key, and
both deadlines. It then returns the grant a caller stores:

| Field | Meaning |
| --- | --- |
| `type` | `GrantView` |
| `owner` | The signer. |
| `grantee` | The granted address. |
| `expires_at_ms` | `grant_expires_at_ms` from the request. |
| `signature` | `grant_signature` from the request. |

The App Proof operation is `ServiceGrantView`.

## `Decrypt`

An owner decrypt is unchanged. The request has no `grant` field. The signer is
the owner. The result type is `Decrypt`: ordered plaintexts and the nullifier
secret. An empty batch still returns that secret.

A grantee decrypt is the same operation, `ServiceDecrypt`, with a `grant`
object:

| Field | Meaning |
| --- | --- |
| `owner` | The address whose notes to open. |
| `grantee` | The signer of this decrypt. |
| `expires_at_ms` | The grant expiry. |
| `signature` | The owner's grant signature. |

The request `signer` is the grantee. The request `signature` is the grantee's
signature over the decrypt approval message. The request digest includes the
grant and omits only the request `signature`. The approval `expires_at_ms`
remains the short deadline.

The enclave checks the grantee's request signature, then the owner's grant
signature over the grant message for this network, this grantee, and this
grant expiry. It checks the grant expiry against its clock. It derives the
viewing key from the note seed and the grant's owner, and opens each item
with that key. The verified grantee does not select the seed.

The result type is `View`:

| Field | Meaning |
| --- | --- |
| `type` | `View` |
| `plaintexts` | Lowercase hex, in the order of `items`. |

The result has no `nullifier_secret` field. An empty grantee batch returns
an empty `plaintexts` array and no secret. The enclave wipes the derived
viewing key and the plaintext result the same way it wipes an owner decrypt.

The SDK rejects a `View` body that contains `nullifier_secret`, and a
`Decrypt` body that lacks it. A `View` reply does not install service keys
and cannot open a later batch or sweep.

## Refusals

The enclave rejects the request when any of these hold:

- The grant expiry is not strictly after the enclave clock.
- `GrantView` is asked for an expiry more than `MAX_GRANT_MS` ahead.
- The grantee fails the Ed25519 address check, or equals the owner.
- The grant signature is not the owner's signature over the grant message.
- A decrypt signer is neither the owner nor the grant's grantee.
- An owner decrypt includes a grant, or a non-owner decrypt omits one.
- The grant's network, grantee, or expiry differs from the signed message.
- The approval deadline fails the existing check.

A refused request returns the existing invalid-request failure and no
plaintexts.
