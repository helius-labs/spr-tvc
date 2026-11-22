import type { DecryptRequest } from "@heliuslabs/spr";

import { DecryptionServiceError } from "../protocol/error.js";
import { encodeLowerHex } from "../protocol/hex.js";
import type { DecryptItem, DecryptLabel } from "../protocol/types.js";

const MAX_ITEMS_PER_BATCH = 256;

const LABELS: Record<DecryptRequest["label"], DecryptLabel> = {
  transfer: "Transfer",
  ringDeposit: "RingDeposit",
};

/** One SDK decrypt request on the wire's terms. */
export function decryptItem(request: DecryptRequest): DecryptItem {
  return {
    ciphertext: encodeLowerHex(request.ciphertext),
    ephemeral_viewing_public_key: encodeLowerHex(request.txViewingPublicKey.toBytes()),
    salt: encodeLowerHex(request.salt),
    slot_index: String(request.slotIndex),
    label: LABELS[request.label],
  };
}

/** Respect both the item ceiling and the executor's serialized byte budget. */
export async function batched<TItem, TAnswer>(
  items: readonly TItem[],
  call: (batch: readonly TItem[]) => Promise<readonly TAnswer[]>,
): Promise<readonly TAnswer[]> {
  const answers: TAnswer[] = [];
  const send = async (batch: readonly TItem[]): Promise<void> => {
    let answer: readonly TAnswer[];
    try {
      answer = await call(batch);
    } catch (error) {
      // RequestTooLarge is raised locally before signing or sending. A
      // single item that cannot fit must fail rather than retry forever.
      if (!(error instanceof DecryptionServiceError) || error.code !== "RequestTooLarge" || batch.length < 2) {
        throw error;
      }
      const middle = Math.floor(batch.length / 2);
      await send(batch.slice(0, middle));
      await send(batch.slice(middle));
      return;
    }
    if (answer.length !== batch.length) throw new DecryptionServiceError("ReleaseBindingMismatch");
    answers.push(...answer);
  };
  for (let start = 0; start < items.length; start += MAX_ITEMS_PER_BATCH) {
    await send(items.slice(start, start + MAX_ITEMS_PER_BATCH));
  }
  return answers;
}

export function checkPlaintexts(values: unknown, items: readonly DecryptItem[]): void {
  if (!Array.isArray(values) || values.length !== items.length) {
    throw new DecryptionServiceError("ReleaseBindingMismatch");
  }
  for (const [index, item] of items.entries()) {
    const value: unknown = values[index];
    if (typeof value !== "string" || value.length !== item.ciphertext.length || /[^0-9a-f]/.test(value)) {
      throw new DecryptionServiceError("ReleaseBindingMismatch");
    }
  }
}
