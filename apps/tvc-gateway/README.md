# tvc-gateway

The decryption gateway. It sits behind gatekeeper and fronts the decryption
enclave. A caller with a Helius API key reaches:

- `POST /v1/decryption/session`
- `POST /v1/decryption/operations`

Session asks the enclave for discovery and a ping, then attaches the Boot
Proof of the replica that answered. Operations forwards the encrypted request
unchanged and attaches the Boot Proof of the replica that signed the reply.
A repeat of the same ciphertext returns the first answer, with
`Idempotent-Replayed: true`.

The private-wallet routes stay on the `private-wallet` branch. This tree does
not enroll wallets or sign descriptors.

## Configuration

Run one network overlay: `--config configs/devnet.yaml` or
`--config configs/mainnet.yaml`. The process loads `config.yaml` beside it,
then the overlay. Secrets come from `TVC_GATEWAY_*`, with nested fields
joined by `__`.

| Variable | Value |
| --- | --- |
| `TVC_GATEWAY_ORIGIN_AUTH_HEADER` | The `Authorization` value gatekeeper sends. At least 32 bytes. |
| `TVC_GATEWAY_TURNKEY__BOOT_PROOF_API_KEY__PUBLIC_KEY` | Turnkey API key in the TVC organization, public half. |
| `TVC_GATEWAY_TURNKEY__BOOT_PROOF_API_KEY__PRIVATE_KEY` | That key's private half. |
| `TVC_GATEWAY_ENCLAVE__BASE_URL` | Decryption enclave URL. Required on mainnet, where the overlay does not pin one yet. |
| `TVC_GATEWAY_ENCLAVE__REPLAY_REDIS_URL` | Optional Redis for the shared replay guard, such as `rediss://host:6379/2`. |

Devnet's overlay pins the decryption enclave
`https://app-67d544db-f727-4c8b-83fe-74a929ac763b.app.turnkey.cloud`.

## Development

The crate is outside the root workspace. `just fmt`, `just lint` and
`just test` cover it.

```sh
cargo test --manifest-path apps/tvc-gateway/Cargo.toml --all-targets --locked
```
