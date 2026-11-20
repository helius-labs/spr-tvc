# Decryption enclave

`PublicKeys` gives a sender the service viewing and nullifier public keys for
a Solana address. `Decrypt` verifies the address owner's signature, opens the
batch with that address's derived viewing key, and seals the result to the
signed response key. See the [security specification](SPEC.md).

| Code | Responsibility |
| --- | --- |
| [`service.rs`](src/service.rs) | Load Turnkey's boot manifest and keys. Serve discovery, encrypted ping, and operations. |
| [`operations.rs`](src/operations.rs) · [`owner.rs`](src/owner.rs) | Check release targeting and verify owner authorization before deriving service keys. |
| [`keys.rs`](src/keys.rs) · [`cipher.rs`](src/cipher.rs) | Derive per-address keys and open SPR ciphertexts. |
| [`request.rs`](src/request.rs) | Open the request envelope, seal the result, and sign its App Proof. |

```sh
cargo test --locked -p spr-tvc-decryption-service
just decryption-e2e
```

Hosted devnet requires a deployment with a matching signed SDK pin. See the
[release runbook](../xtask/README.md) and
[test invariants](../tests/README.md#decryption-service).
