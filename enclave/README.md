# Decryption service

The decryption service lets an unregistered Solana address receive a private
transfer. The enclave derives a viewing key from the verified recipient
address. The recipient signs the exact batch and a one-time response key.
Only the holder of that response private key can open the reply.

- [Send, receive, and trust model](SPEC.md)
- [TypeScript client](../sdk/README.md)
- [Wire protocol](../protocol/README.md#decryption-service)
- [Test invariants](../tests/README.md#decryption-service)

## Devnet

The [devnet endpoint](deploy/release.json) requires a release with a signed
SDK pin. Run `just decryption-e2e` or `just headless-e2e` for local verification.

The [devnet app](deploy/devnet/spr-decryption-service-devnet.app.json) has its
own Quorum key, with a 2-of-3 split provisioned using devnet operator key
files. See [operator tooling](../xtask/README.md) for releases.

## Audit entry points

- [Enclave request flow](src/operations.rs) checks the release and signature
  before deriving the recipient's keys and sealing the response.
- [Address eligibility](src/owner.rs), [service key derivation](src/keys.rs),
  and [pool cipher checks](src/cipher.rs) handle the
  individual trust boundaries.
- [SDK connection verification](../sdk/src/connection/connect.ts)
  checks the release and replica. The [operation exchange](../sdk/src/client/exchange.ts)
  binds the request and response key before asking the owner to sign.
- [SDK wallet keys](../sdk/src/client/keys.ts)
  route decryption to the service and derive transaction keys locally.

```sh
cargo test -p spr-tvc-decryption-service --locked
just decryption-e2e
just headless-e2e
```

The [unregistered-recipient example](../example/index.ts)
sends, claims, and sweeps a transfer. `just headless-e2e` runs it on localnet
with the unattested service testkit.
