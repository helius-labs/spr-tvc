# Changelog

## 0.2.0-alpha.0

Simplify the v1 wire format and bind release signing to the approved deployment manifest.
One owner signature covers an indexer page. The encrypted body cap is 10 MiB, the same cap as the indexer, and the client splits a decrypt only when a batch would exceed it. The client drops the attested session after every HTTP failure.

## 0.1.0-alpha.0

Standalone SPR decryption client with direct enclave transport, signed
release policy and attestation verification, and an SPR wallet-key adapter.
