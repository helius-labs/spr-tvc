import {
  SOL_MINT,
  Wallet,
  buildDepositTransaction,
  buildTransferTransaction,
  syncWallet,
} from "@heliuslabs/spr";
import { isWalletRegistered } from "@heliuslabs/spr/wallet";

import { expectBalance, localWalletKeys, sendAndConfirmFactory, serviceSpendKeys, setup } from "./setup.js";

const AMOUNT = 3_000_000n;

async function main(): Promise<void> {
  const { zolana, service, sender, recipient } = await setup();
  if (await isWalletRegistered({ rpc: zolana, owner: recipient.address })) {
    throw new Error("the example requires a recipient without a registry record");
  }
  const serviceKeys = await service.keys(recipient);
  let keys: Awaited<ReturnType<typeof localWalletKeys>> | undefined;
  let ownKeys: typeof keys;
  let spendKeys: Awaited<ReturnType<typeof serviceSpendKeys>> | undefined;
  try {
    keys = await localWalletKeys(sender, zolana.proofService);
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

    const transfer = await buildTransferTransaction({
      client: zolana,
      wallet,
      keys,
      feePayer: sender.address,
      recipient: serviceKeys.address(),
      amount: AMOUNT,
    });
    const transferTx = await send(transfer);

    // The recipient signs, the service decrypts, the SDK keeps what matches its commitment.
    const received = new Wallet({ identity: serviceKeys.address() });
    await syncWallet({
      client: zolana,
      wallet: received,
      keys: serviceKeys,
      config: { requireSlot: transferTx.slot },
    });
    expectBalance("receive", received.balance(SOL_MINT), AMOUNT, 1);

    ownKeys = sender.address === recipient.address
      ? keys
      : await localWalletKeys(recipient, zolana.proofService);
    spendKeys = await serviceSpendKeys(serviceKeys, zolana.proofService);
    const sweep = await buildTransferTransaction({
      client: zolana,
      wallet: received,
      keys: spendKeys,
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
    console.log(`sweep recipient=${recipient.address} private_balance=${AMOUNT} tx=${sweepTx.signature}`);
  } finally {
    spendKeys?.destroy();
    serviceKeys.destroy();
    if (ownKeys !== keys) ownKeys?.destroy();
    keys?.destroy();
  }
}

await main();
