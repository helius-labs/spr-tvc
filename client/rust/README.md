# spr-tvc-client

The Rust client of the decryption service. `OperationsClient` is the gatekeeper path. `DecryptionClient` dials an enclave URL and fetches Boot Proofs itself. The [spec](../../docs/spec.md) is the path and the trust assumptions.

```sh
cargo test --locked -p spr-tvc-client
```

[Examples](../../examples/rust)
