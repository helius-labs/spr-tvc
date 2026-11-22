import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { NitroPolicy, NitroTarget } from "@heliuslabs/spr-decryption-service/nitro";
import { checkpointStore, nativeDevnet, requireOriginalPolicy } from "../nitro.js";

test("native rehearsal requires both buckets to agree on the accepted original-only policy", () => {
  const target: NitroTarget = {
    endpoint: "https://original.example/", releaseId: "old",
    executableSha256: "11".repeat(32), custodyEpoch: "1", custodyDigest: "22".repeat(32),
    pcrs: { 0: "11".repeat(48), 1: "22".repeat(48), 2: "33".repeat(48), 3: "44".repeat(48) },
  };
  const replacement = { ...target, endpoint: "https://replacement.example/", releaseId: "new", custodyEpoch: "2" };
  const policy: NitroPolicy = {
    version: 1, action: "activate", network: "devnet", securityDomainId: "33".repeat(32),
    noteSeedCommitment: "44".repeat(32), minimumCustodyEpoch: "1", sequence: "1", previousPolicyDigest: null,
    validFromMs: "1", expiresAtMs: "10", targets: [target, { ...target, endpoint: "https://original-b.example/" }],
  };
  const checkpoint = { sequence: "1", digest: "55".repeat(32), minimumCustodyEpoch: "1" };
  const published = { agreed: true, checkpoint, policy, validFrom: 1n, expiresAt: 10n };
  requireOriginalPolicy(published, checkpoint, 2n);
  for (const candidate of [
    { ...published, agreed: false },
    { ...published, checkpoint: { ...checkpoint, digest: "66".repeat(32) } },
    { ...published, policy: { ...policy, targets: [target, replacement] } },
    { ...published, policy: { ...policy, targets: [replacement] } },
  ]) {
    assert.throws(() => requireOriginalPolicy(candidate, checkpoint, 2n), /original custody epoch only/);
  }
  assert.throws(() => requireOriginalPolicy(published, undefined, 2n), /original custody epoch only/);
});

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
