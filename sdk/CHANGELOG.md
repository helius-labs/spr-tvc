# Changelog

## 0.2.0-alpha.0

Simplify the v1 wire format and bind release signing to the approved deployment manifest.
Native Nitro trust pins require the exact policy digest for their minimum revision. The SDK also stores a current quorum-signed revocation witnessed on either pinned bucket. Custom stores apply `advancesNitroPolicy` and persist the complete checkpoint, including a revocation at the same sequence as an activation.
Payment resolution checks the Solana genesis hash after each registry read, including reads that return a registered recipient. An unregistered recipient must still have the same payment keys under the current service policy after the registry recheck.
Native Nitro checks the published policy before sending an address for lookup and before returning service keys for payment or recovery.
Destroying a key handle cancels pending decryption and proof calls and clears any derived keys it has yet to return.
The client verifies the owner signature against the exact request before sending it to the enclave.

## 0.1.0-alpha.0

Standalone SPR decryption client with direct enclave transport, signed
release policy and attestation verification, and an SPR wallet-key adapter.
