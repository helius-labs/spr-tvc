# Decryption enclave

`PublicKeys` returns the viewing and nullifier public keys for a Solana address. Anyone can ask. `Decrypt` checks the owner's signature, opens the notes with that address's viewing key, and seals the plaintexts and the nullifier secret to the response key in the request.

The process starts only after Turnkey's Quorum OS has loaded an approved manifest and the configured Quorum key. From there it serves discovery, an encrypted ping, and operations.

The [security specification](SPEC.md) is who is trusted with what. [Wire](../wire/README.md) is the byte layout.

```sh
cargo test --locked -p spr-tvc-decryption-service
just decryption-e2e
```
