# spr-tvc

A sender can pay a Solana address before its owner has a shielded wallet. The decryption enclave holds a viewing key for that address. The owner signs each batch. The enclave returns the plaintexts sealed to a key the owner's wallet just created.

The transfer publishes the recipient's Solana address. That is how the wallet finds the notes.

The enclave derives the keys and opens the notes. It runs inside a Turnkey Nitro enclave. Callers with a Helius API key reach it through the gateway. `POST /v1/decryption/session` identifies the replica. `POST /v1/decryption/operations` forwards the encrypted request and returns that replica's Boot Proof. A client checks the proof before sending a note, and again on every reply.

[Enclave](decryption-service) · [Gateway](gateway) · [Wire](wire) · [Security specification](decryption-service/SPEC.md)

The TypeScript and Rust clients look up the service address, open notes, and fetch the nullifier secret when a spend has not opened notes yet.

[TypeScript client](client/sdk) · [Rust client](client/rust) · [Examples](examples/rust)

[Turnkey example](examples/turnkey) deposits, sends, claims, and sweeps.

`just ci` runs the Rust and TypeScript suites, including a loopback decrypt. `just decryption-e2e` runs the client examples against that enclave. `just headless-e2e` adds a local Solana validator and runs the Turnkey flow. Releases are in the [runbook](xtask/README.md).

`publish-tvc-gateway-image.yml` still builds the private-wallet gateway from the `private-wallet` branch. It does not publish this gateway.
