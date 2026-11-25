# Rust decryption client

|  |  |
| --- | --- |
| [`service_address`](examples/service_address.rs) | The shielded address a sender pays before the owner registers. |
| [`open_note`](examples/open_note.rs) | The owner opens one note. |
| [`open_batch`](examples/open_batch.rs) | The owner opens two notes in one decrypt. |
| [`nullifier_secret`](examples/nullifier_secret.rs) | A spend fetches the nullifier secret without opening notes. |
| [`gatekeeper`](examples/gatekeeper.rs) | The same open through the gatekeeper. |

The first four talk to the loopback enclave. `gatekeeper` needs `SPR_E2E_GATEKEEPER_URL`, `HELIUS_API_KEY` or `API_KEY`, and `SPR_E2E_RELEASE_PIN`.

```sh
just decryption-e2e
cargo run -p spr-tvc-rust-example --example service_address
cargo run -p spr-tvc-rust-example --example open_note
cargo run -p spr-tvc-rust-example --example open_batch
cargo run -p spr-tvc-rust-example --example nullifier_secret
cargo run -p spr-tvc-rust-example --example gatekeeper
```
