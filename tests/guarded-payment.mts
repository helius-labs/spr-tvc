import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  LocalKeys,
  SOL_MINT,
  USER_REGISTRY_PROGRAM_ID,
  Wallet,
  buildDepositTransaction,
  buildTransferTransaction,
  createSprClient,
  syncWallet,
  type Bytes32,
} from "@heliuslabs/spr";
import { getUserRecordAddress } from "@heliuslabs/spr/addresses";
import { ed25519DerivationMessage } from "@heliuslabs/spr/keypair";
import { buildRegistrationTransaction, isWalletRegistered } from "@heliuslabs/spr/wallet";
import type { DecryptionServiceKeys } from "@heliuslabs/spr-decryption-service";
import { createLocalDecryptionService } from "@heliuslabs/spr-decryption-service/testing";
import {
  assertIsSendableTransaction,
  createKeyPairSignerFromBytes,
  createSignableMessage,
  decompileTransactionMessage,
  generateKeyPairSigner,
  getAddressEncoder,
  getCompiledTransactionMessageDecoder,
  getSignatureFromTransaction,
  sendTransactionWithoutConfirmingFactory,
  signTransactionWithSigners,
  type KeyPairSigner,
  type Signature,
  type Transaction,
} from "@solana/kit";

function loopback(name: string): URL {
  const value = process.env[name];
  assert(value, "missing " + name);
  const url = new URL(value);
  assert.equal(url.protocol, "http:");
  assert.equal(url.hostname, "127.0.0.1");
  return url;
}

const amount = 3_000_000n;
const client = await createSprClient({
  solanaRpcUrl: loopback("ZOLANA_ENDPOINT").href,
  indexerUrl: loopback("ZOLANA_INDEXER_URL").href,
  proverUrl: loopback("ZOLANA_PROVER_URL").href,
  proofDataSource: "client",
  commitment: "finalized",
  indexerConfig: { poll: { numRetries: 120, delayMs: 250n, maxDelayMs: 2_000n } },
});
const service = createLocalDecryptionService({
  network: "devnet",
  endpoint: loopback("DECRYPTION_SERVICE_LOCAL_ENDPOINT"),
  genesisHash: await client.getGenesisHash(),
});

async function payerFromFile(): Promise<KeyPairSigner> {
  const path = process.env["TVC_SOLANA_KEYPAIR_PATH"];
  assert(path, "missing TVC_SOLANA_KEYPAIR_PATH");
  const values: unknown = JSON.parse(await readFile(path, "utf8"));
  assert(Array.isArray(values) && values.length === 64);
  assert(values.every((byte: unknown) => typeof byte === "number" && Number.isInteger(byte) && byte >= 0 && byte <= 255));
  const bytes = Uint8Array.from(values);
  try {
    return await createKeyPairSignerFromBytes(bytes);
  } finally {
    bytes.fill(0);
    values.fill(0);
  }
}

async function keysFor(signer: KeyPairSigner): Promise<LocalKeys> {
  const key = Uint8Array.from(getAddressEncoder().encode(signer.address)) as Bytes32;
  const [signatures] = await signer.signMessages([createSignableMessage(ed25519DerivationMessage(key))]);
  const derivationSeed = signatures?.[signer.address];
  assert(derivationSeed);
  try {
    return LocalKeys.fromDerivationSeed({ solanaPublicKey: signer.address, derivationSeed }, client.proofService);
  } finally {
    derivationSeed.fill(0);
  }
}

const payer = await payerFromFile();
const recipient = await generateKeyPairSigner();
const recipientRecord = await getUserRecordAddress(recipient.address);
const broadcast = sendTransactionWithoutConfirmingFactory({ rpc: client.solanaRpc });

async function send(transaction: Transaction, ...signers: KeyPairSigner[]): Promise<bigint> {
  const signed = await signTransactionWithSigners([payer, ...signers], transaction);
  assertIsSendableTransaction(signed);
  await broadcast(signed, { commitment: client.commitment, preflightCommitment: client.commitment });
  return client.confirmTransaction(getSignatureFromTransaction(signed));
}

async function register(signer: KeyPairSigner, keys: LocalKeys): Promise<bigint> {
  const transaction = await buildRegistrationTransaction({
    client, owner: signer.address, payer: payer.address, address: keys.address(),
  });
  assert(transaction);
  return signer === payer ? send(transaction) : send(transaction, signer);
}

function signGuarded(transaction: Transaction, abortSignal: AbortSignal, ...owners: KeyPairSigner[]) {
  const compiled = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
  assert.equal(compiled.version, 1);
  const message = decompileTransactionMessage(compiled);
  const assertion = message.instructions.at(-1);
  assert(assertion);
  assert.equal(assertion.programAddress, USER_REGISTRY_PROGRAM_ID);
  assert.equal(assertion.data?.[0], 3);
  assert.deepEqual(assertion.accounts?.map(account => account.address), [recipientRecord]);
  return signTransactionWithSigners([payer, ...owners], transaction, { abortSignal });
}

async function sync(wallet: Wallet, keys: LocalKeys | DecryptionServiceKeys, requireSlot: bigint) {
  await syncWallet({ client, wallet, keys, config: { requireSlot } });
}

const payerKeys = await keysFor(payer);
let recipientKeys: LocalKeys | undefined;
let recovered: DecryptionServiceKeys | undefined;
try {
  const registeredKeys = await keysFor(recipient);
  recipientKeys = registeredKeys;
  await register(payer, payerKeys);
  const depositor = new Wallet({ identity: payerKeys.address() });
  const deposit = await buildDepositTransaction({
    client, feePayer: payer.address, recipient: payerKeys.address(), amount: amount * 2n,
  });
  await sync(depositor, payerKeys, await send(deposit));
  assert.equal(await isWalletRegistered({ rpc: client, owner: recipient.address }), false);
  assert.equal(await client.getBalance(recipient.address), 0n);

  const transfer = {
    client, wallet: depositor, keys: payerKeys, feePayer: payer.address,
    recipient: recipient.address, amount, decryptionService: service,
  };
  const payment = await buildTransferTransaction(transfer);
  await sync(depositor, payerKeys, await client.confirmTransaction(await payment.send(signGuarded)));
  assert.equal(depositor.balance(SOL_MINT).amount, amount);

  const stale = await buildTransferTransaction(transfer);
  let signedId: Signature | undefined;
  let registeredAt: bigint | undefined;
  await assert.rejects(stale.send(async (transaction, signal) => {
    const signed = await signGuarded(transaction, signal);
    signedId = getSignatureFromTransaction(signed);
    registeredAt = await register(recipient, registeredKeys);
    return signed;
  }), { code: "WALLET_SUBMIT_PAYMENT", causeCode: "WALLET_DECRYPTION_RECIPIENT_MISMATCH" });
  assert(signedId && registeredAt !== undefined);
  assert.equal((await client.solanaRpc.getSignatureStatuses([signedId]).send()).value[0], null);
  await sync(depositor, payerKeys, registeredAt);
  assert.equal(depositor.balance(SOL_MINT).amount, amount);

  recovered = await service.open(recipient, client.proofService);
  const original = new Wallet({ identity: recovered.address() });
  await sync(original, recovered, registeredAt);
  assert.equal(original.balance(SOL_MINT).amount, amount);
  const sweep = await buildTransferTransaction({
    ...transfer, wallet: original, keys: recovered,
    decryptionService: {
      genesisHash: service.genesisHash,
      async address() { throw new Error("registered payment used the service lookup"); },
    },
  });
  const sweepSignature = await sweep.send((transaction, signal) =>
    signGuarded(transaction, signal, recipient),
  );
  const sweptAt = await client.confirmTransaction(sweepSignature);
  const destination = new Wallet({ identity: registeredKeys.address() });
  await Promise.all([sync(original, recovered, sweptAt), sync(destination, registeredKeys, sweptAt)]);
  assert.equal(original.balance(SOL_MINT).amount, 0n);
  assert.equal(destination.balance(SOL_MINT).amount, amount);
  assert.equal(await client.getBalance(recipient.address), 0n);
} finally {
  recovered?.destroy();
  recipientKeys?.destroy();
  payerKeys.destroy();
}

console.log("Guarded send, rejection, recovery and sweep passed");
