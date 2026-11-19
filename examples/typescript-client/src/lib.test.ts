import assert from "node:assert/strict";
import { test } from "node:test";

import {
  blockhash,
  compileTransaction,
  createSignableMessage,
  createTransactionMessage,
  generateKeyPairSigner,
  getTransactionEncoder,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
} from "@solana/kit";
import { turnkeySigner } from "./turnkey.js";

test("Turnkey signs the exact Ed25519 message without a separate hash", async () => {
  const owner = await generateKeyPairSigner();
  const message = createSignableMessage(Uint8Array.of(0xff, 0x00, 0x12));
  const [expected] = await owner.signMessages([message]);
  const signature = Buffer.from(expected![owner.address]!).toString("hex");
  const signer = turnkeySigner({
    async signRawPayload(input) {
      assert.deepEqual(input, {
        signWith: owner.address,
        payload: "ff0012",
        encoding: "PAYLOAD_ENCODING_HEXADECIMAL",
        hashFunction: "HASH_FUNCTION_NOT_APPLICABLE",
      });
      return { r: signature.slice(0, 64), s: signature.slice(64) };
    },
    async signTransaction() { assert.fail("a message is signed as a raw payload"); },
  }, owner.address);

  assert.deepEqual(await signer.signMessages([message]), [expected]);
});

test("the adapter refuses a signature from another account", async () => {
  const owner = await generateKeyPairSigner();
  const other = await generateKeyPairSigner();
  const message = createSignableMessage(Uint8Array.of(0xff, 0x00, 0x12));
  const [result] = await other.signMessages([message]);
  const signature = Buffer.from(result![other.address]!).toString("hex");
  const signer = turnkeySigner({
    async signRawPayload() { return { r: signature.slice(0, 64), s: signature.slice(64) }; },
    async signTransaction() { assert.fail("a message is signed as a raw payload"); },
  }, owner.address);
  await assert.rejects(signer.signMessages([message]), /different message or account/);
});

test("Turnkey's transaction signature must cover the original Solana message", async () => {
  const owner = await generateKeyPairSigner();
  const lifetime = { blockhash: blockhash("11111111111111111111111111111111"), lastValidBlockHeight: 1n };
  const message = setTransactionMessageFeePayer(owner.address, createTransactionMessage({ version: 0 }));
  const transaction = compileTransaction(setTransactionMessageLifetimeUsingBlockhash(lifetime, message));
  const [expected] = await owner.signTransactions([transaction]);
  const encoder = getTransactionEncoder();
  const unsignedTransaction = Buffer.from(encoder.encode(transaction)).toString("hex");
  const changedTransaction = compileTransaction(setTransactionMessageLifetimeUsingBlockhash(
    { ...lifetime, blockhash: blockhash(owner.address) },
    message,
  ));
  let changed = false;
  const signer = turnkeySigner({
    async signRawPayload() { assert.fail("a transaction uses Turnkey's Solana parser"); },
    async signTransaction(input) {
      assert.deepEqual(input, {
        signWith: owner.address,
        type: "TRANSACTION_TYPE_SOLANA",
        unsignedTransaction,
      });
      const result = changed ? changedTransaction : transaction;
      const signedTransaction = encoder.encode({ ...result, signatures: expected! });
      return { signedTransaction: Buffer.from(signedTransaction).toString("hex") };
    },
  }, owner.address);
  assert.deepEqual(await signer.signTransactions([transaction]), [expected]);
  changed = true;
  await assert.rejects(signer.signTransactions([transaction]), /changed the transaction message/);
});
