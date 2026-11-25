import type { DecryptRequest } from "@heliuslabs/spr";

import { DecryptionServiceError } from "../protocol/error.js";
import { encodeLowerHex, requireHex } from "../protocol/hex.js";
import type { DecryptItem, DecryptLabel } from "../protocol/types.js";

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
    kdf: "HkdfSha256Ctr",
  };
}

/** Split when the serialized request would exceed the executor's byte budget. */
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
    if (answer.length !== batch.length) throw new Error("BatchMismatch");
    answers.push(...answer);
  };
  if (items.length > 0) await send(items);
  return answers;
}

export function checkHexList(values: unknown, count: number, bytes?: number): asserts values is string[] {
  if (!Array.isArray(values) || values.length !== count) {
    throw new DecryptionServiceError("ReleaseBindingMismatch");
  }
  for (const value of values) requireHex(value, bytes);
}
