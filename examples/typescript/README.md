# TypeScript client

These programs run against the loopback enclave from `just decryption-e2e`. The [spec](../../docs/spec.md) is how the deployed service works.

`service_address` asks for the shielded address a sender pays. `open_note` opens one note. `open_batch` opens two, in order. `nullifier_secret` fetches the spend secret without opening notes. `gatekeeper` opens one note through a deployed gateway. It needs `SPR_E2E_GATEKEEPER_URL`, `HELIUS_API_KEY` or `API_KEY`, and `SPR_E2E_RELEASE_PIN`.

```sh
just decryption-e2e
pnpm --filter spr-tvc-typescript-sdk-example example examples/open_note.ts
```
