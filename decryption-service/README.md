# Decryption enclave

This process derives a viewing key and a nullifier key for a Solana address, opens notes for an owner who signed the batch, and seals the reply to the wallet's response key. It starts only after Quorum OS has loaded an approved manifest and the configured Quorum key.

Production callers reach it through the public edge proxy and the gateway. The [spec](../docs/spec.md) is that path and the trust assumptions. [Wire](../wire/README.md) is the byte layout.

```sh
cargo test --locked -p spr-tvc-decryption-service
just decryption-e2e
```
