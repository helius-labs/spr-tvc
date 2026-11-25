# TypeScript decryption client

|  |  |
| --- | --- |
| [`service_address`](examples/service_address.ts) | The shielded address a sender pays before the owner registers. |
| [`open_note`](examples/open_note.ts) | The owner opens one note. |
| [`open_batch`](examples/open_batch.ts) | The owner opens two notes in one decrypt. |
| [`nullifier_secret`](examples/nullifier_secret.ts) | A spend fetches the nullifier secret without opening notes. |
| [`gatekeeper`](examples/gatekeeper.ts) | The same open through the gatekeeper. |

The first four talk to the loopback enclave. `gatekeeper` needs `SPR_E2E_GATEKEEPER_URL`, `HELIUS_API_KEY` or `API_KEY`, and `SPR_E2E_RELEASE_PIN`.

```sh
just decryption-e2e
pnpm --filter spr-tvc-typescript-sdk-example example examples/service_address.ts
pnpm --filter spr-tvc-typescript-sdk-example example examples/open_note.ts
pnpm --filter spr-tvc-typescript-sdk-example example examples/open_batch.ts
pnpm --filter spr-tvc-typescript-sdk-example example examples/nullifier_secret.ts
pnpm --filter spr-tvc-typescript-sdk-example example examples/gatekeeper.ts
```
