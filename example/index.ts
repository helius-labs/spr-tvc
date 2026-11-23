import { signTransactionWithSigners } from "@solana/kit";
import {
  SOL_MINT,
  Wallet,
  buildDepositTransaction,
  buildTransferTransaction,
  syncWallet,
} from "@heliuslabs/spr";
import { buildRegistrationTransaction, isWalletRegistered } from "@heliuslabs/spr/wallet";
import { resolvePaymentAddress, type DecryptionServiceKeys } from "@heliuslabs/spr-decryption-service";

import { expectBalance, localWalletKeys, sendAndConfirmFactory, setup } from "./setup.js";

const AMOUNT = 3_000_000n;

async function main(): Promise<void> {
  const { zolana, service, sender, recipient, nitro, localnet } = await setup();
  let serviceKeys: DecryptionServiceKeys | undefined;
  let keys: Awaited<ReturnType<typeof localWalletKeys>> | undefined;
  let ownKeys: typeof keys;
  try {
    async function checkRecipient(registered: boolean) {
      if (await isWalletRegistered({ rpc: zolana, owner: recipient.address }) !== registered) {
        throw new Error(`expected recipient registration to be ${registered}`);
      }
      if (sender.address !== recipient.address && (await zolana.solanaRpc.getBalance(recipient.address).send()).value !== 0n) {
        throw new Error("the fresh recipient must remain unfunded");
      }
    }
    await checkRecipient(false);
    keys = await localWalletKeys(sender, zolana.proofService);
    const send = sendAndConfirmFactory(zolana, sender);
    if (localnet) {
      const registration = await buildRegistrationTransaction({ client: zolana, owner: sender.address, address: keys.address() });
      if (registration) await send(registration);
      if (!await isWalletRegistered({ rpc: zolana, owner: sender.address })) throw new Error("sender did not register");
    }
    const requireOriginalPaymentPolicy = await nitro?.prepareTransfer();

    const wallet = new Wallet({ identity: keys.address() });
    const deposit = await buildDepositTransaction({
      client: zolana,
      feePayer: sender.address,
      recipient: localnet ? sender.address : keys.address(),
      amount: AMOUNT,
    });
    const depositTx = await send(deposit);
    await syncWallet({ client: zolana, wallet, keys, config: { requireSlot: depositTx.slot } });

    let paidTo: Awaited<ReturnType<typeof service.address>> | undefined;
    const transfer = await buildTransferTransaction({
      client: zolana,
      wallet,
      keys,
      feePayer: sender.address,
      recipient: recipient.address,
      amount: AMOUNT,
      decryptionService: {
        genesisHash: service.genesisHash,
        async address(owner, options) {
          const resolved = await service.address(owner, options);
          paidTo = resolved;
          return resolved;
        },
        confirmAddress(owner, expected, options) {
          return service.confirmAddress(owner, expected, options);
        },
      },
    });
    if (paidTo === undefined) throw new Error("the transfer did not resolve a service address");
    const transferSignature = await transfer.send(async (transaction) => {
      const signed = await signTransactionWithSigners([sender], transaction);
      await requireOriginalPaymentPolicy?.();
      return signed;
    });
    const transferTx = {
      signature: transferSignature,
      slot: await zolana.confirmTransaction(transferSignature),
    };
    const finalizedAt = BigInt(Date.now());
    if (nitro) console.log(`finalized transfer recipient=${recipient.address} tx=${transferTx.signature} awaiting ${nitro.seedChanged ? "the seed cutover" : "the replacement custody epoch"}`);
    const replacement = await nitro?.afterTransfer(paidTo, finalizedAt);
    const reader = replacement?.service ?? service;
    await checkRecipient(false);
    ownKeys = sender.address === recipient.address
      ? keys
      : await localWalletKeys(recipient, zolana.proofService);
    const sweepSend = sender.address === recipient.address ? send : sendAndConfirmFactory(zolana, sender, recipient);
    if (localnet) {
      const registration = await buildRegistrationTransaction({
        client: zolana, owner: recipient.address, address: ownKeys.address(), payer: sender.address,
      });
      if (!registration) throw new Error("expected a new recipient registration");
      await sweepSend(registration);
      await checkRecipient(true);
      const registered = await resolvePaymentAddress({ rpc: zolana, owner: recipient.address, service: {
        genesisHash: service.genesisHash,
        async address() { throw new Error("a registered owner must use its registry address"); },
      } });
      if (!Buffer.from(registered.toBytes()).equals(ownKeys.address().toBytes())) {
        throw new Error("the new recipient payment keys do not match the registry");
      }
    }

    serviceKeys = await reader.open(recipient, zolana.proofService);
    const received = new Wallet({ identity: serviceKeys.address() });
    await syncWallet({
      client: zolana,
      wallet: received,
      keys: serviceKeys,
      config: { requireSlot: transferTx.slot },
    });
    expectBalance("receive", received.balance(SOL_MINT), AMOUNT, 1);
    await replacement?.requireSamePolicy();

    const sweep = await buildTransferTransaction({
      client: zolana,
      wallet: received,
      keys: serviceKeys,
      feePayer: sender.address,
      recipient: localnet ? recipient.address : ownKeys.address(),
      amount: AMOUNT,
    });
    const sweepTx = await sweepSend(sweep, replacement?.requireSamePolicy);
    const own = new Wallet({ identity: ownKeys.address() });
    const sweepSlot = { requireSlot: sweepTx.slot };
    await Promise.all([
      syncWallet({ client: zolana, wallet: own, keys: ownKeys, config: sweepSlot }),
      syncWallet({ client: zolana, wallet: received, keys: serviceKeys, config: sweepSlot }),
    ]);
    expectBalance("swept source", received.balance(SOL_MINT), 0n, 0);
    expectBalance("sweep", own.balance(SOL_MINT), AMOUNT, 1);
    await checkRecipient(localnet === true);
    const boot = replacement?.bootKeyId ? ` transfer=${transferTx.signature} boot=${replacement.bootKeyId}` : "";
    console.log(`sweep recipient=${recipient.address} private_balance=${AMOUNT} tx=${sweepTx.signature}${boot}`);
  } finally {
    serviceKeys?.destroy();
    if (ownKeys !== keys) ownKeys?.destroy();
    keys?.destroy();
    nitro?.close();
  }
}

await main();
