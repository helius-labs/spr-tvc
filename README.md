# spr-tvc

A sender can pay a Solana address before its owner has a shielded wallet. The decryption enclave holds a viewing key for that address. The owner signs each batch. The enclave returns the plaintexts sealed to a key the owner's wallet just created.

The transfer publishes the recipient's Solana address. That is how the wallet finds the notes.

The enclave is firewalled. Wallets call the public Helius edge proxy, which admits an API key and forwards to the gateway. The gateway calls the enclave and Turnkey. The [spec](docs/spec.md) is the path, the checks, and the security assumptions.

[Enclave](decryption-service) · [Gateway](gateway) · [Wire](wire) · [TypeScript client](client/sdk) · [Rust client](client/rust)

[Examples](examples/rust) open a note against a loopback enclave. [Turnkey example](examples/turnkey) deposits, sends, claims, and sweeps.

`just ci` runs the Rust and TypeScript suites, including a loopback decrypt. `just decryption-e2e` runs the client examples against that enclave. `just headless-e2e` adds a local Solana validator and runs the Turnkey flow. Releases are in the [runbook](xtask/README.md).

`publish-tvc-gateway-image.yml` still builds the private-wallet gateway from the `private-wallet` branch. It does not publish this gateway.
