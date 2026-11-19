# spr-tvc

Attested decryption for Solana Privacy Rings. A sender can make a private
transfer to a Turnkey Solana account before its owner registers a shielded
wallet. The owner authorizes each decryption with that account's signature.

| Component | Role |
| --- | --- |
| [Decryption enclave](apps/decryption-service) | Derives per-address keys, verifies the owner, and encrypts replies to the signed response key. |
| [TypeScript client](packages/decryption-service) | Verifies the release and replica, builds signed requests, and exposes the service identity as SPR `WalletKeys`. |
| [Turnkey example](examples/typescript-client) | Signs directly with a Turnkey Solana account and sends, claims, and sweeps notes. |

The [specification](apps/decryption-service/SPEC.md) describes the security
boundaries. The [wire protocol](crates/protocol/README.md) pins the encoding
and the [test invariants](TEST_INVARIANTS.md) map the guarantees to coverage.

```sh
just ci
just decryption-e2e
just headless-e2e
```

The [release guide](scripts/README.md#release) covers image publication,
provisioning, and signing the SDK pin. The direct devnet endpoint is in
[`deploy/release.json`](apps/decryption-service/deploy/release.json).
Use disposable funds on devnet.
