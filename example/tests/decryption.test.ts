import assert from "node:assert/strict";
import { test } from "node:test";

import { SOL_MINT, ViewingKey, Wallet, initializePoseidon } from "@heliuslabs/spr";
import { DEFAULT_TREE_ID } from "@heliuslabs/spr/interface";
import { randomSalt } from "@heliuslabs/spr/keypair";
import {
  AssetRegistry,
  createProofOutput,
  decryptTransactions,
  encodeConfidentialSlots,
  type IndexedShieldedTransaction,
} from "@heliuslabs/spr/transaction";
import { createLocalDecryptionService } from "@heliuslabs/spr-decryption-service/testing";
import { address, generateKeyPairSigner, type Signature } from "@solana/kit";

const endpoint = process.env["DECRYPTION_SERVICE_LOCAL_ENDPOINT"];

test("the direct service opens signed batches and the SDK checks commitments", { skip: !endpoint }, async () => {
  await initializePoseidon();
  const service = createLocalDecryptionService({ network: "devnet", endpoint: new URL(endpoint!) });
  const signer = await generateKeyPairSigner();
  const approvals: string[] = [];
  const owner = {
    address: signer.address,
    signMessages: async (messages: Parameters<typeof signer.signMessages>[0]) => {
      approvals.push(Buffer.from(messages[0]!.content).toString("hex"));
      return signer.signMessages(messages);
    },
  };
  const keys = await service.decrypt(owner);
  const sender = ViewingKey.generate();
  try {
    assert.equal(approvals.length, 0);
    const recipient = await service.address(owner.address);
    assert.deepEqual(keys.address().viewingPublicKey.toBytes(), recipient.viewingPublicKey.toBytes());
    assert.deepEqual(keys.address().nullifierPublicKey, recipient.nullifierPublicKey);
    const output = (amount: bigint) => createProofOutput({ ownerAddress: recipient, asset: SOL_MINT, amount });
    const notes = [output(5n), output(7n)];
    const salt = randomSalt();
    const slots = encodeConfidentialSlots(notes, new AssetRegistry(), sender, salt);
    const tree = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
    const transaction: IndexedShieldedTransaction = {
      slot: 1n,
      txSignature: "1".repeat(64) as Signature,
      txViewingPublicKey: sender.publicKey(),
      salt,
      outputSlots: slots.map((slot, index) => ({
        viewTag: slot!.viewTag,
        payload: slot!.data,
        outputContext: { hash: (index === 0 ? notes[0]! : output(8n)).hash(DEFAULT_TREE_ID), tree, leafIndex: BigInt(index) },
      })),
      messages: [],
      nullifiers: [],
      proofless: false,
    };
    const wallet = new Wallet({ identity: keys.address() });
    const report = await decryptTransactions({ wallet, keys, transactions: [transaction] });
    assert.equal(report.undecryptableCandidates, 1);
    assert.deepEqual(wallet.utxos().map(({ utxo }) => utxo.amount), [5n]);
    assert.equal(approvals.length, 1);
  } finally {
    keys.destroy();
    sender.destroy();
  }
});
