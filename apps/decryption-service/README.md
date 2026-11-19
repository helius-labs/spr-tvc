# Decryption service

The decryption service lets an unregistered Solana address receive a private
transfer. The enclave derives a viewing key from the verified recipient
address. The recipient signs the exact batch and a one-time response key.
Only the holder of that response private key can open the reply.

- [Send, receive, and trust model](SPEC.md)
- [TypeScript client](../../packages/tvc-wallet/README.md#decryption-service)
- [Wire protocol](../../crates/protocol/README.md#decryption-service)
- [Test invariants](../../TEST_INVARIANTS.md#decryption-service)

## Devnet

Connect to the devnet enclave endpoint in [`deploy/release.json`](deploy/release.json)
with a Turnkey Boot Proof resolver. A gateway configured for `/v1/decryption`
can supply those proofs. Devnet uses disposable funds.

The [devnet app](deploy/devnet/spr-decryption-service-devnet.app.json) has its
own Quorum key, with a 2-of-3 split provisioned using devnet operator key
files. For release steps, see [operator tooling](../../scripts/README.md#release)
and pass `--app decryption-service`.

## Audit entry points

- [Enclave request flow](src/operations.rs) checks the release and signature
  before deriving the recipient's keys and sealing the response.
- [Address eligibility](src/owner.rs), [service key derivation](src/keys.rs),
  and [pool cipher checks](../../crates/enclave/src/cipher.rs) handle the
  individual trust boundaries.
- [SDK connection verification](../../packages/tvc-wallet/src/client/connection.ts)
  and the [service client](../../packages/tvc-wallet/src/decryption-service/client.ts)
  verify the replica and construct signed requests.

```sh
cargo test -p spr-tvc-decryption-service -p spr-tvc-enclave --locked
just gateway-e2e
just headless-e2e
```

The [unregistered-recipient example](../../examples/typescript-client/examples/unregistered_recipient.ts)
sends, claims, and sweeps a transfer. `just headless-e2e` runs it on localnet
with the unattested service testkit.
