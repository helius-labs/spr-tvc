# Changelog

## 0.2.0-alpha.0

Simplify the v1 wire format and bind release signing to the approved deployment manifest.
Native Nitro trust pins require the exact policy digest for their minimum revision. Custom stores apply both authenticated publication heads in `NitroPolicyStore.accept(update)`.
Payment resolution checks the Solana genesis hash before the service lookup and after the registry recheck. An unregistered recipient must still have the same payment keys under the current service policy after both RPC reads.
Destroying a key handle cancels pending decryption and proof calls and clears any derived keys it has yet to return.

## 0.1.0-alpha.0

Standalone SPR decryption client with direct enclave transport, signed
release policy and attestation verification, and an SPR wallet-key adapter.
