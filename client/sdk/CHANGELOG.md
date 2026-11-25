# Changelog

## 0.2.0-alpha.0

Simplify the v1 wire format and bind release signing to the approved deployment manifest.
One owner signature covers an indexer page. The encrypted body cap is 10 MiB, the same cap as the indexer, and the client splits a decrypt only when a batch would exceed it. The client drops the attested session after every HTTP failure. Live release checks are exported from `@heliuslabs/spr-decryption-service/release`. The shared types are exported from `@heliuslabs/spr-decryption-service/wire`. The `./testing` entry is only the local unattested testkit. An owner can sign a view grant of at most 30 minutes. The grantee attaches it to `Decrypt` and receives the same nullifier secret. Owner decrypts are unchanged. Every decrypt item names its KDF. The only mode is `HkdfSha256Ctr`. `keys` returns the shielded keys and does not call Decrypt. The first note decrypt returns the plaintexts and the nullifier secret together. A spend that has not opened notes fetches that secret once. It does not prove; the secret goes to the SPR prover. Requests are encrypted with Turnkey's quorum-key envelope, and the Nitro signature and certificate chain use Turnkey's verifier. The client still pins PCR0–3, PCR17, and the manifest digest. `createGatekeeperDecryptionService` posts `/v1/decryption/session`, then `keys` and `decrypt` to `/v1/decryption/operations`. The session bundles discovery, the ping, and the Boot Proof, and each operation reply brings the Boot Proof for the replica that signed it.

## 0.1.0-alpha.0

Standalone SPR decryption client with direct enclave transport, signed
release policy and attestation verification, and an SPR wallet-key adapter.
