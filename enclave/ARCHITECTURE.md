# QuorumOS decryption service

A sender can pay a Solana address before its owner registers a shielded wallet.
The enclave derives that owner's viewing and nullifier keys from the QuorumOS
quorum key and the Solana address. Replacing the pivot keeps the same quorum
key, so existing notes stay openable. Each boot still generates a fresh
ephemeral key. Wallets check the signed release policy and the Boot Proof
before encrypting to that boot.

QuorumOS holds the threshold shares, approves the manifest, and forwards the
quorum key into a measured enclave. Turnkey hosts that ceremony. The release
authorities separately sign which deployment wallets may use. The owner signs
each decrypt batch and its response key.

A self-hosted custody ledger, a second publisher, and a raw Nitro image would
repeat the manifest approval and key forwarding QuorumOS already provides.
This tree keeps one boot path: the QuorumOS pivot.
