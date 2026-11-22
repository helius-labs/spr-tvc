# Changelog

## 0.2.0-alpha.0

Simplify the v1 wire format and bind release signing to the approved deployment manifest.
Native Nitro trust pins require the exact policy digest for their minimum revision. Custom stores apply both authenticated publication heads in `NitroPolicyStore.accept(update)`.
Payment resolution checks that the service and the payment RPC use the same Solana genesis hash.
Destroying a key handle cancels pending decryption and proof calls and clears any derived keys it has yet to return.

## 0.1.0-alpha.0

Standalone SPR decryption client with direct enclave transport, signed
release policy and attestation verification, and an SPR wallet-key adapter.
