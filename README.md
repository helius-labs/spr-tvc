# spr-tvc

Attested decryption for Solana Privacy Rings. A sender can make a confidential
transfer to a Turnkey Solana account before its owner registers a shielded
wallet. The owner authorizes each decryption with that account's signature.
In this flow the note contents are encrypted and the recipient's Solana
owner tag is public.

| Component | Role |
| --- | --- |
| [Decryption enclave](enclave) | Derives per-address keys, verifies the owner, and encrypts replies to the signed response key. |
| [Wire protocol](protocol) | Defines the signed request and encrypted reply, with shared Rust and TypeScript fixtures. |
| [TypeScript client](sdk) | Verifies the release and replica, builds signed requests, and exposes the service identity as SPR `WalletKeys`. |
| [Turnkey example](example) | Signs directly with a Turnkey Solana account and sends, claims, and sweeps notes. |

The [specification](enclave/SPEC.md) describes the security boundaries.
The [test invariants](tests/README.md) link each guarantee to its coverage.

```sh
just ci
just decryption-e2e
just headless-e2e
```

The [release guide](scripts/README.md#release) covers image publication,
provisioning, and signing the SDK pin. Hosted use requires a signed pin for the
approved deployment. The [mainnet release procedure](scripts/README.md#mainnet)
covers staging, independent signatures, and recovery.
