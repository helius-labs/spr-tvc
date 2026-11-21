import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { checkpointStore, nativeDevnet } from "../nitro.js";

test("native rehearsal checkpoints survive closing the database and exclude earlier custody floors", async () => {
  const directory = await mkdtemp(join(tmpdir(), "spr-nitro-checkpoint-"));
  try {
    const path = join(directory, "wallet.sqlite");
    const trust = { network: "devnet" as const, securityDomainId: "11".repeat(32) };
    const first = { sequence: "3", digest: "33".repeat(32), minimumCustodyEpoch: "2" };
    const writer = checkpointStore(path, trust);
    try {
      assert.equal(await writer.store.accept(first), true);
    } finally {
      writer.close();
    }
    const reader = checkpointStore(path, trust);
    try {
      assert.deepEqual({ ...await reader.store.current() }, first);
      assert.equal(await reader.store.accept({ ...first, digest: "44".repeat(32) }), false);
      assert.equal(await reader.store.accept({ ...first, sequence: "4", minimumCustodyEpoch: "1" }), false);
    } finally {
      reader.close();
    }
    const unrelated = checkpointStore(path, { ...trust, securityDomainId: "22".repeat(32) });
    try {
      assert.equal(await unrelated.store.current(), undefined);
    } finally {
      unrelated.close();
    }
  } finally {
    await rm(directory, { recursive: true });
  }
});

test("native rehearsal rejects mainnet wallet trust before opening the database", async () => {
  const directory = await mkdtemp(join(tmpdir(), "spr-nitro-trust-"));
  try {
    const trust = join(directory, "wallet.json");
    await writeFile(trust, '{"network":"mainnet"}');
    await assert.rejects(nativeDevnet(trust, join(directory, "wallet.sqlite"), "2"), /requires devnet wallet trust/);
  } finally {
    await rm(directory, { recursive: true });
  }
});
