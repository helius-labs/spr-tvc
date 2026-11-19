# Decryption service

The decryption service lets an unregistered Solana address receive a private
transfer. The enclave derives a viewing key from the verified recipient
address. The recipient signs the exact batch and a one-time response key.
Only the holder of that response private key can open the reply.

- [Send, receive, and trust model](SPEC.md)
- [TypeScript client](../../packages/decryption-service/README.md#decryption-service)
- [Wire protocol](../../crates/protocol/README.md#decryption-service)
- [Test invariants](../../TEST_INVARIANTS.md#decryption-service)

## Devnet

Connect to the devnet enclave endpoint in [`deploy/release.json`](deploy/release.json)
with a Turnkey Boot Proof resolver. Devnet uses disposable funds.

The [devnet app](deploy/devnet/spr-decryption-service-devnet.app.json) has its
own Quorum key, with a 2-of-3 split provisioned using devnet operator key
files. See [operator tooling](../../scripts/README.md#release) for releases.

## Audit entry points

- [Enclave request flow](src/operations.rs) checks the release and signature
  before deriving the recipient's keys and sealing the response.
- [Address eligibility](src/owner.rs), [service key derivation](src/keys.rs),
  and [pool cipher checks](../../crates/enclave/src/cipher.rs) handle the
  individual trust boundaries.
- [SDK connection verification](../../packages/decryption-service/src/client/connection.ts)
  checks the release and replica. The [operation exchange](../../packages/decryption-service/src/decryption-service/exchange.ts)
  binds the request and response key before asking the owner to sign.
- [SDK wallet keys](../../packages/decryption-service/src/decryption-service/keys.ts)
  route decryption to the service and derive transaction keys locally.

```sh
cargo test -p spr-tvc-decryption-service -p spr-tvc-enclave --locked
just decryption-e2e
just headless-e2e
```

The [unregistered-recipient example](../../examples/typescript-client/examples/unregistered_recipient.ts)
sends, claims, and sweeps a transfer. `just headless-e2e` runs it on localnet
with the unattested service testkit.
