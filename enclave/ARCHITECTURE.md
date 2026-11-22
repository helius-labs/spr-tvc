# Why native Nitro for decryption

A sender should be able to pay a Solana address before its owner registers a
shielded wallet. The owner should still be able to open that note after we
replace every enclave that was running when it was created. That makes note-key
recovery part of the payment protocol.

**Keep note keys stable across upgrades.** The enclave derives a wallet's
viewing and nullifier keys from a seed and its Solana address. Each boot creates
fresh request-encryption and response-signing keys. Replacing an enclave rotates
the connection keys while the owner keeps access to existing notes.

**Separate custody, release approval and owner authorization.** Two of three
custody approval signers approve the exact enclave that may receive shares.
Any three of the six custodians can then provision it. Both KMS decrypt
responses are sealed to attested enclaves. The epoch relay verifies the
share commitment and the pinned quorum's approval of the exact destination.
Rotation keeps the seed and issues fresh shares to six fresh recovery keys.
Custodian accounts may stay the same. A separate release quorum approves the enclaves wallets can
use. The owner signs each decrypt batch and its response key. The host relays
wrapped shares and encrypted operations.

**Make upgrades explicit.** A signed policy can authorize old and new replicas
during an upgrade. The SDK verifies fresh Nitro evidence before encrypting to
a replica and records the highest accepted policy sequence in the wallet's
durable store. After a custody rotation, wallets advance their custody floor.
Operators can republish a previously approved image for the current custody
epoch under a newer signed policy. Recovering the same seed restores access
to the same notes.

**Keep the runtime small.** Nitro and KMS give us measured execution and
attested secret delivery. QuorumOS would also provide threshold provisioning
and key forwarding. For this service, independent custody and signed release
policies cover the controls we need. The tradeoff is that we own the custody
ceremony, rollout and recovery drills, and rely on AWS for attestation.

The two-host AWS rehearsal reopened a synthetic note after stopping the old
enclave. The 3-of-6 rotation rehearsal used one AWS account. The sealed relay flow across
six independent accounts and a devnet send, claim and sweep across an upgrade
remain to be verified.

[Security specification](NITRO.md) · [Deployment runbook](deploy/nitro/README.md) · [Audit evidence](../tests/AUDIT.md)
