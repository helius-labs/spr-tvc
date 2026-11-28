# Gateway

The public edge proxy checks a Helius API key and calls this process with its origin credential and the project id. This process calls the firewalled enclave and Turnkey.

`POST /v1/decryption/operations` forwards the encrypted request unchanged and attaches the Boot Proof of the replica that signed the reply. The same ciphertext returns the first answer, with `Idempotent-Replayed: true`.

The [spec](../docs/spec.md) is the full path. The HTTP contract is [openapi.json](openapi.json).

Wallet enrollment stays on the `private-wallet` branch.

## Configuration

Pass one overlay: `--config configs/devnet.yaml` or `--config configs/mainnet.yaml`. The process loads `config.yaml` beside the binary, then the overlay. Secrets come from `TVC_GATEWAY_*`. Nested fields are joined by `__`.

| Variable | Value |
| --- | --- |
| `TVC_GATEWAY_ORIGIN_AUTH_HEADER` | The `Authorization` value the edge proxy sends. At least 32 bytes. |
| `TVC_GATEWAY_TURNKEY__BOOT_PROOF_API_KEY__PUBLIC_KEY` | Turnkey API key in the TVC organization, public half. |
| `TVC_GATEWAY_TURNKEY__BOOT_PROOF_API_KEY__PRIVATE_KEY` | That key's private half. |
| `TVC_GATEWAY_ENCLAVE__BASE_URL` | Decryption enclave URL. Required on mainnet. Devnet's overlay pins one. |
| `TVC_GATEWAY_ENCLAVE__REPLAY_REDIS_URL` | Optional Redis for the shared replay guard, such as `rediss://host:6379/2`. |

Devnet pins `https://app-67d544db-f727-4c8b-83fe-74a929ac763b.app.turnkey.cloud`.

The crate is outside the root workspace. `just fmt`, `just lint`, and `just test` include it.

```sh
cargo test --manifest-path gateway/Cargo.toml --all-targets --locked
```
