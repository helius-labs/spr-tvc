// Covers INV-07 (pre-signing batch splitting, order preservation, incomplete result refusal).

import { expect, it, vi } from "vitest";

import { DecryptionServiceError } from "../../src/wire/error.js";
import { batched } from "../../src/client/items.js";

it("sends a full indexer page as one batch and preserves the result order", async () => {
  const items = Array.from({ length: 1000 }, (_, i) => i);
  const call = vi.fn(async (batch: readonly number[]) => batch.map((value) => value + 1));
  expect(await batched(items, call)).toEqual(items.map((value) => value + 1));
  expect(call.mock.calls.map(([batch]) => batch.length)).toEqual([1000]);
});

it("splits only on the pre-signing byte limit and stops on any other refusal", async () => {
  const tooLarge = new DecryptionServiceError("RequestTooLarge");
  const call = vi.fn(async (batch: readonly number[]) => {
    if (batch.length > 1) throw tooLarge;
    return batch;
  });
  expect(await batched([1, 2, 3], call)).toEqual([1, 2, 3]);
  expect(call.mock.calls.map(([batch]) => batch)).toEqual([[1, 2, 3], [1], [2, 3], [2], [3]]);
  await expect(batched([1], async () => { throw tooLarge; })).rejects.toBe(tooLarge);
  const rejected = new DecryptionServiceError("OperationRejected");
  const refuse = vi.fn(async () => { throw rejected; });
  await expect(batched([1, 2], refuse)).rejects.toBe(rejected);
  expect(refuse).toHaveBeenCalledTimes(1);
});

it("refuses incomplete results and does not send an empty batch", async () => {
  const call = vi.fn(async () => []);
  expect(await batched([], call)).toEqual([]);
  expect(call).not.toHaveBeenCalled();
  await expect(batched([1], call)).rejects.toThrow("BatchMismatch");
});
