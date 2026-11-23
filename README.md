# spr-tvc

Attested decryption for Solana Privacy Rings (SPR). A sender can pay a Solana
address before its owner registers a shielded wallet. The owner signs each
decrypt batch, including its deadline and the wallet's one-time reply key.
The enclave verifies the signature and encrypts the reply to that key before
the deadline. The transfer publishes the recipient's Solana address as its
owner tag.

| Start here | |
| --- | --- |
| [Architecture](enclave/ARCHITECTURE.md) | QuorumOS boots the enclave and forwards its key across upgrades |
| [Security specification](enclave/SPEC.md) | Data flow, key custody, and trust assumptions |
| [Decryption enclave](enclave) · [Wire protocol](protocol) | Implementation and exact cryptographic inputs |
| [TypeScript client](sdk) · [Turnkey example](example) | Connect, send, claim, and sweep |
| [Test invariants](tests/INVARIANTS.md) | What the automated tests pin |

Run `just ci` for Rust and TypeScript checks, including the SDK-to-enclave
loopback test. Run `just headless-e2e` for send, claim, and sweep on localnet.

The enclave builds with the released `spr-keypair` crate. To build the
loopback binary for another checkout, run `just build-local-binary`. CI
packages the Linux x86-64 binary and its SHA-256 checksum. Pin the archive
checksum in the consuming checkout before installing it. The binary binds
only to loopback and uses public test keys.
