import assert from "node:assert/strict";
import { test } from "node:test";
import { setup } from "../setup.js";

test("the demonstration refuses mainnet before contacting any service", async () => {
  const previous = process.env["SPR_NETWORK"];
  process.env["SPR_NETWORK"] = "mainnet";
  try {
    await assert.rejects(setup(), /limited to devnet and localnet/);
  } finally {
    if (previous === undefined) delete process.env["SPR_NETWORK"];
    else process.env["SPR_NETWORK"] = previous;
  }
});
