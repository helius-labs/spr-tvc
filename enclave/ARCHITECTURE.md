# Why native Nitro for decryption

A sender should be able to pay a Solana address before its owner registers a
shielded wallet. The owner should still be able to open that note after we
replace every enclave that was running when it was created. That makes note-key
recovery part of the payment protocol.

**Keep note keys stable across upgrades.** The enclave derives a wallet's
viewing and nullifier keys from a seed and its Solana address. Each boot creates
fresh request-encryption and response-signing keys. Replacing an enclave rotates
the connection keys while the owner keeps access to existing notes.

**Separate custody, release approval and owner authorization.** Six custodians
each hold one encrypted share. Any three can approve an enclave to recover the
seed. A measured rotation reissues six shares under fresh or retained custodian
keys while keeping the same note seed. A separate signer quorum approves the
releases wallets can use. For each decrypt batch, the owner signs the request
and its response key. The host relays wrapped shares and encrypted operations.

**Make upgrades explicit.** A signed policy can authorize old and new replicas
during an upgrade. The SDK verifies fresh Nitro evidence before encrypting to
a replica and records the highest accepted policy sequence in the wallet's
durable store. After a custody rotation, wallets advance their custody floor.
Operators can roll back to a previously approved image within a trusted epoch. A failed rollout can interrupt service. Recovering the same
shares restores access to the same notes.

**Keep the runtime small.** Nitro and KMS give us measured execution and
attested secret delivery. QuorumOS would also provide threshold provisioning
and key forwarding. For this service, independent custody and signed release
policies cover the controls we need. The tradeoff is that we own the custody
ceremony, rollout and recovery drills, and rely on AWS for attestation.

The two-host AWS rehearsal reopened the same synthetic note after retiring the
old enclave. Separate custody accounts and a real devnet send, claim and sweep across an
upgrade remain part of qualification.

[Security specification](NITRO.md) · [Deployment runbook](deploy/nitro/README.md) · [Audit evidence](../tests/AUDIT.md)
