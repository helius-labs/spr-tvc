import {
  SOL_MINT,
  Wallet,
  buildDepositTransaction,
  buildTransferTransaction,
  syncWallet,
} from "@heliuslabs/spr";
import { isWalletRegistered } from "@heliuslabs/spr/wallet";
import type { DecryptionServiceKeys } from "@heliuslabs/spr-decryption-service";

import { expectBalance, localWalletKeys, sendAndConfirmFactory, setup } from "./setup.js";

const AMOUNT = 3_000_000n;

async function main(): Promise<void> {
  const { zolana, service, sender, recipient, nitro } = await setup();
  let serviceKeys: DecryptionServiceKeys | undefined;
  let keys: Awaited<ReturnType<typeof localWalletKeys>> | undefined;
  let ownKeys: typeof keys;
  try {
    async function checkRecipient() {
      if (await isWalletRegistered({ rpc: zolana, owner: recipient.address })) {
        throw new Error("the example requires a recipient without a registry record");
      }
      if (sender.address !== recipient.address && (await zolana.solanaRpc.getBalance(recipient.address).send()).value !== 0n) {
        throw new Error("the fresh recipient must remain unfunded");
      }
    }
    await checkRecipient();
    const recipientAddress = await service.address(recipient.address);
    await nitro?.beforeSend();
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
      recipient: recipientAddress,
      amount: AMOUNT,
    });
    const transferTx = await send(transfer);
    if (nitro) console.log(`transfer recipient=${recipient.address} tx=${transferTx.signature} awaiting the replacement custody epoch`);
    const reader = nitro ? await nitro.afterTransfer(recipient.address) : service;
    serviceKeys = await reader.open(recipient, zolana.proofService);

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
    await checkRecipient();
    console.log(`sweep recipient=${recipient.address} private_balance=${AMOUNT} tx=${sweepTx.signature}`);
  } finally {
    serviceKeys?.destroy();
    if (ownKeys !== keys) ownKeys?.destroy();
    keys?.destroy();
    nitro?.close();
  }
}

await main();
