import {
  SOL_MINT,
  Wallet,
  buildDepositTransaction,
  buildTransferTransaction,
  syncWallet,
} from "@heliuslabs/spr";
import { isWalletRegistered } from "@heliuslabs/spr/wallet";

import { expectBalance, localWalletKeys, sendAndConfirmFactory, setup } from "../src/lib.js";

const AMOUNT = 3_000_000n;

async function main(): Promise<void> {
  const { zolana, service, sender, recipient } = await setup();
  const keys = await localWalletKeys(sender, zolana.proofService);
  const send = sendAndConfirmFactory(zolana, sender);

  const wallet = new Wallet({ identity: keys.address() });
  const deposit = await buildDepositTransaction({
    client: zolana,
    feePayer: sender.address,
    recipient: keys.address(),
    amount: AMOUNT,
  });
  const depositTx = await send(deposit);
  await syncWallet({ client: zolana, wallet, keys, config: { requireSlot: depositTx.slot } });

  // The recipient has no registry record, so the sender pays its service keys.
  if (await isWalletRegistered({ rpc: zolana, owner: recipient.address })) {
    throw new Error("a new address has a registry record");
  }
  const transfer = await buildTransferTransaction({
    client: zolana,
    wallet,
    keys,
    feePayer: sender.address,
    recipient: await service.address(recipient.address),
    amount: AMOUNT,
  });
  const transferTx = await send(transfer);

  // The recipient signs, the service decrypts, the SDK keeps what matches its commitment.
  const serviceKeys = await service.open(recipient, zolana.proofService);
  const received = new Wallet({ identity: serviceKeys.address() });
  await syncWallet({
    client: zolana,
    wallet: received,
    keys: serviceKeys,
    config: { requireSlot: transferTx.slot },
  });
  expectBalance("receive", received.balance(SOL_MINT), AMOUNT, 1);

  const ownKeys = sender.address === recipient.address
    ? keys
    : await localWalletKeys(recipient, zolana.proofService);
  const sweep = await buildTransferTransaction({
    client: zolana,
    wallet: received,
    keys: serviceKeys,
    feePayer: sender.address,
    recipient: ownKeys.address(),
    amount: AMOUNT,
  });
  const sweepSend = sender.address === recipient.address ? send : sendAndConfirmFactory(zolana, sender, recipient);
  const sweepTx = await sweepSend(sweep);
  const own = new Wallet({ identity: ownKeys.address() });
  await syncWallet({
    client: zolana,
    wallet: own,
    keys: ownKeys,
    config: { requireSlot: sweepTx.slot },
  });
  expectBalance("sweep", own.balance(SOL_MINT), AMOUNT, 1);
  serviceKeys.destroy();
  if (ownKeys !== keys) ownKeys.destroy();
  keys.destroy();
  console.log(`sweep recipient=${recipient.address} private_balance=${AMOUNT} tx=${sweepTx.signature}`);
}

await main();
