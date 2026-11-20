# spr-tvc

Attested decryption for Solana Privacy Rings. A sender can make a confidential
transfer to a Turnkey Solana account before its owner registers a shielded
wallet. The owner authorizes each decryption with that account's signature.
In this flow the note contents are encrypted and the recipient's Solana
owner tag is public.

| Component | Role |
| --- | --- |
| [Decryption enclave](enclave) | Derives per-address keys, verifies the owner, and encrypts replies to the signed response key. |
| [Wire protocol](protocol) | Defines the signed request and encrypted reply, with shared Rust and TypeScript fixtures. |
| [TypeScript client](sdk) | Verifies the release and replica, builds signed requests, and exposes the service identity as SPR `WalletKeys`. |
| [Turnkey example](example) | Signs directly with Turnkey and sends, claims, and sweeps notes. |
| [Release tooling](xtask) | Stages deployments and verifies live attestation before writing SDK pins. |

Run `just ci` for Rust and TypeScript tests, fixture verification, and a
loopback SDK-to-enclave test. Run `just headless-e2e` for the full localnet
send, claim, and sweep flow.

- [Security specification](enclave/SPEC.md)
- [Tests and invariants](tests/README.md)
- [Release runbook](xtask/README.md)
