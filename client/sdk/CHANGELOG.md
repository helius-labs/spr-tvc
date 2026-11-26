# Changelog

## 0.2.0-alpha.0

`createDecryptionService` posts `keys` and `decrypt` to `/v1/decryption/operations`. The request names the Quorum key in the signed pin. Each reply carries the Boot Proof of the replica that signed it. The client requires the pinned manifest set to have approved that manifest, then checks the Nitro document, PCR0–3, PCR17, and the App Proof before opening the result. An image upgrade on the same Quorum key, PCRs, and manifest set needs no client release.

One owner signature covers an indexer page. The body cap is 10 MiB, and the client splits a decrypt only when a batch would exceed it. `keys` returns the shielded keys. The first decrypt of notes also returns the nullifier secret. A view grant lasts at most 30 minutes and names the Quorum key. Live release checks are exported from `@heliuslabs/spr-decryption-service/release`, the shared types from `@heliuslabs/spr-decryption-service/wire`, and `./testing` is the local unattested testkit. The package is AGPL-3.0-only.

## 0.1.0-alpha.0

Standalone SPR decryption client with direct enclave transport, signed
release policy and attestation verification, and an SPR wallet-key adapter.
