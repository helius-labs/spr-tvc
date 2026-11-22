import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { NitroPolicy, NitroTarget, NitroPolicyCheckpoint } from "@heliuslabs/spr-decryption-service/nitro";
import { acceptedReplacementPolicy, checkpointStore, nativeDevnet, requireOriginalPolicy } from "../nitro.js";

function agreed(checkpoint: NitroPolicyCheckpoint, previousPolicyDigest: string | null) {
  const revision = { checkpoint, previousPolicyDigest };
  return [revision, revision] as const;
}

test("native rotation rehearsal checks both published policies and the exact serving epochs", () => {
  const target: NitroTarget = {
    endpoint: "https://original.example/", releaseId: "old",
    executableSha256: "11".repeat(32), custodyEpoch: "1", custodyDigest: "22".repeat(32),
    pcrs: { 0: "11".repeat(48), 1: "22".repeat(48), 2: "33".repeat(48), 3: "44".repeat(48), 4: "56".repeat(48) },
  };
  const replacement = { ...target, endpoint: "https://replacement.example/", releaseId: "new", custodyEpoch: "2" };
  const policy: NitroPolicy = {
    version: 1, action: "activate", recoveryOnly: false, network: "devnet", securityDomainId: "33".repeat(32),
    noteSeedCommitment: "44".repeat(32), minimumCustodyEpoch: "1", sequence: "1", previousPolicyDigest: null,
    validFromMs: "1", expiresAtMs: "10", targets: [target, { ...target, endpoint: "https://original-b.example/" }],
  };
  const checkpoint = { sequence: "1", digest: "55".repeat(32), recoveryOnly: false, minimumCustodyEpoch: "1" };
  const published = { agreed: true, checkpoint, policy, validFrom: 1n, expiresAt: 10n };
  requireOriginalPolicy(published, checkpoint, 2n);
  for (const candidate of [
    { ...published, agreed: false },
    { ...published, policy: { ...policy, recoveryOnly: true } },
    { ...published, checkpoint: { ...checkpoint, digest: "66".repeat(32) } },
    { ...published, policy: { ...policy, targets: [target, replacement] } },
    { ...published, policy: { ...policy, targets: [replacement] } },
  ]) {
    assert.throws(() => requireOriginalPolicy(candidate, checkpoint, 2n), /original custody epoch only/);
  }
  assert.throws(() => requireOriginalPolicy(published, undefined, 2n), /original custody epoch only/);

  const nextCheckpoint = { ...checkpoint, sequence: "2", digest: "77".repeat(32), minimumCustodyEpoch: "2" };
  const replacementPolicy = {
    ...policy, sequence: nextCheckpoint.sequence, minimumCustodyEpoch: nextCheckpoint.minimumCustodyEpoch,
    previousPolicyDigest: checkpoint.digest, targets: [replacement],
  };
  const next = { ...published, checkpoint: nextCheckpoint, policy: replacementPolicy };
  const later = { ...replacement, endpoint: "https://later.example/", custodyEpoch: "3" };
  assert.equal(acceptedReplacementPolicy(next, nextCheckpoint, "2"), true);
  assert.equal(acceptedReplacementPolicy(next, checkpoint, "2"), false);
  assert.equal(acceptedReplacementPolicy({ ...next, agreed: false }, nextCheckpoint, "2"), false);
  for (const targets of [[later], [replacement, later]]) {
    assert.equal(acceptedReplacementPolicy({ ...next, policy: { ...replacementPolicy, targets } }, nextCheckpoint, "2"), false);
  }
});

test("native rehearsal checkpoints survive closing the database and exclude earlier custody floors", async () => {
  const directory = await mkdtemp(join(tmpdir(), "spr-nitro-checkpoint-"));
  try {
    const path = join(directory, "wallet.sqlite");
    const trust = { network: "devnet" as const, securityDomainId: "11".repeat(32) };
    const first = { sequence: "3", digest: "33".repeat(32), recoveryOnly: true, minimumCustodyEpoch: "2" };
    const writer = checkpointStore(path, trust);
    try {
      assert.equal(await writer.store.accept(agreed(first, "22".repeat(32))), true);
    } finally {
      writer.close();
    }
    const reader = checkpointStore(path, trust);
    try {
      assert.deepEqual({ ...await reader.store.current() }, first);
      assert.equal(await reader.store.accept(agreed({ ...first, digest: "44".repeat(32) }, "22".repeat(32))), false);
      assert.equal(await reader.store.accept(agreed({ ...first, sequence: "4", minimumCustodyEpoch: "1" }, first.digest)), false);
      assert.equal(await reader.store.accept(agreed({ ...first, sequence: "4", recoveryOnly: false }, first.digest)), false);
      assert.equal(await reader.store.accept(agreed({ ...first, sequence: "4" }, "22".repeat(32))), false);
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

test("seed cutover refuses a reused domain or seed commitment", async () => {
  const directory = await mkdtemp(join(tmpdir(), "spr-nitro-cutover-"));
  try {
    const original = join(directory, "old.json");
    const next = join(directory, "new.json");
    const trust = { network: "devnet", securityDomainId: "11".repeat(32), noteSeedCommitment: "22".repeat(32) };
    await writeFile(original, JSON.stringify(trust));
    for (const candidate of [
      { ...trust, noteSeedCommitment: "33".repeat(32) },
      { ...trust, securityDomainId: "44".repeat(32) },
      { ...trust, securityDomainId: "44".repeat(32), noteSeedCommitment: "33".repeat(32), recoveryOnly: true },
    ]) {
      await writeFile(next, JSON.stringify(candidate));
      await assert.rejects(nativeDevnet(original, join(directory, "wallet.sqlite"), { walletTrust: next }), /different domain and seed commitment/);
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
    await assert.rejects(nativeDevnet(trust, join(directory, "wallet.sqlite"), { epoch: "2" }), /requires devnet wallet trust/);
  } finally {
    await rm(directory, { recursive: true });
  }
});
