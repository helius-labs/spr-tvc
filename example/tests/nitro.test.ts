import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import type { NitroPolicy, NitroTarget, NitroPolicyCheckpoint } from "@heliuslabs/spr-decryption-service/nitro";
import {
  acceptedReplacementPolicy, checkpointStore, nativeDevnet, parseRetirementReport,
  requireCurrentPolicy, requireOriginalPolicy, requireRetirementPolicy, waitForRetirement,
} from "../nitro.js";

test("the retirement canary binds the transfer to the exact retired custody record and a later boot", async context => {
  const original = { custodyEpoch: "2", custodyDigest: "12".repeat(32) };
  const scope = { network: "devnet" as const, securityDomainId: "34".repeat(32), original, transferredAt: 1_999n, replacementEpoch: "3" };
  const bootKeyId = "ab".repeat(32);
  const walletPolicyDigest = "cd".repeat(32);
  const custodyDigest = "ef".repeat(32);
  const bootstrap = { bootedAtMs: "3001", bootKeyId, slots: [2, 4, 6] };
  const retired = {
    ...original, network: scope.network, securityDomainId: scope.securityDomainId, publishedAtMs: "2000",
  };
  const replacement = { custodyEpoch: "3", custodyDigest, walletPolicyDigest, replacementBootstrap: bootstrap };
  const report = { retired, retirementObservedAtMs: "3000", replacement };
  const parse = (candidate: unknown) => parseRetirementReport(JSON.stringify(candidate), scope);

  assert.deepEqual(parse(report), { bootKeyId, walletPolicyDigest, custodyDigest });
  for (const change of [
    { network: "mainnet" },
    { securityDomainId: "56".repeat(32) },
    { custodyEpoch: "1" },
    { custodyDigest: "23".repeat(32) },
  ]) {
    assert.throws(() => parse({ ...report, retired: { ...retired, ...change } }), /custody domain and epochs/);
  }
  assert.throws(() => parse({ ...report, retired: undefined }), /custody domain and epochs/);
  assert.throws(() => parse({ ...report, replacement: { ...replacement, custodyEpoch: "4" } }), /custody domain and epochs/);
  for (const publishedAtMs of ["1000", "1999", "4000"]) {
    assert.throws(() => parse({ ...report, retired: { ...retired, publishedAtMs } }), /after the confirmed transfer and before verification/);
  }
  assert.throws(() => parse({ ...report, retirementObservedAtMs: bootstrap.bootedAtMs }), /later boot from three custody slots/);
  for (const slots of [[2, 2, 6], [2, 4, 7], [2, 4], [1, 2, 4, 6]]) {
    assert.throws(() => parse({
      ...report, replacement: { ...replacement, replacementBootstrap: { ...bootstrap, slots } },
    }), /later boot from three custody slots/);
  }
  const directory = await mkdtemp(join(tmpdir(), "spr-nitro-retirement-"));
  context.after(() => rm(directory, { recursive: true }));
  const path = join(directory, "report.json");
  await assert.rejects(waitForRetirement(directory, scope), /expected a regular JSON document/);
  await writeFile(path, Buffer.alloc(256 * 1024 + 1));
  await assert.rejects(waitForRetirement(path, scope), /exceeds 256 KiB/);
  await writeFile(path, Buffer.from([0xff]));
  await assert.rejects(waitForRetirement(path, scope), { code: "ERR_ENCODING_INVALID_ENCODED_DATA" });
  await writeFile(path, JSON.stringify(report));
  assert.deepEqual(await waitForRetirement(path, scope), parse(report));
});

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
    publications: [
      { bucket: "release-primary", region: "eu-north-1", account: "000000000001" },
      { bucket: "release-mirror", region: "eu-west-1", account: "000000000002" },
    ],
    validFromMs: "1", expiresAtMs: "10", targets: [target, { ...target, endpoint: "https://original-b.example/" }],
  };
  const checkpoint = { sequence: "1", digest: "55".repeat(32), recoveryOnly: false, minimumCustodyEpoch: "1" };
  const published = { sameEnvelope: true, checkpoint, policy, validFrom: 1n, expiresAt: 10n };
  assert.deepEqual(requireOriginalPolicy(published, checkpoint, 2n), {
    custodyEpoch: target.custodyEpoch, custodyDigest: target.custodyDigest,
  });
  for (const candidate of [
    { ...published, sameEnvelope: false },
    { ...published, policy: { ...policy, recoveryOnly: true } },
    { ...published, checkpoint: { ...checkpoint, digest: "66".repeat(32) } },
    { ...published, policy: { ...policy, targets: [target, replacement] } },
    { ...published, policy: { ...policy, targets: [target, { ...target, custodyDigest: "99".repeat(32) }] } },
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
  assert.equal(acceptedReplacementPolicy({ ...next, sameEnvelope: false }, nextCheckpoint, "2"), false);
  for (const targets of [[later], [replacement, later]]) {
    assert.equal(acceptedReplacementPolicy({ ...next, policy: { ...replacementPolicy, targets } }, nextCheckpoint, "2"), false);
  }

  const report = { walletPolicyDigest: nextCheckpoint.digest, custodyDigest: replacement.custodyDigest, bootKeyId: "88".repeat(32) };
  requireRetirementPolicy(next, report);
  assert.throws(() => requireRetirementPolicy(next, { ...report, walletPolicyDigest: checkpoint.digest }), /differs from the verified retirement report/);
  assert.throws(() => requireRetirementPolicy(next, { ...report, custodyDigest: "99".repeat(32) }), /differs from the verified retirement report/);

  requireCurrentPolicy(next, nextCheckpoint, nextCheckpoint);
  assert.throws(() => requireCurrentPolicy(next, checkpoint, nextCheckpoint), /policy changed during the rehearsal/);
  assert.throws(() => requireCurrentPolicy(published, nextCheckpoint, nextCheckpoint), /policy changed during the rehearsal/);
  assert.throws(() => requireCurrentPolicy({ ...next, sameEnvelope: false }, nextCheckpoint, nextCheckpoint), /policy changed during the rehearsal/);
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

test("native rehearsal refuses to replace a corrupt checkpoint", async () => {
  const directory = await mkdtemp(join(tmpdir(), "spr-nitro-checkpoint-"));
  const path = join(directory, "wallet.sqlite");
  const trust = { network: "devnet" as const, securityDomainId: "11".repeat(32) };
  const checkpoint = { sequence: "3", digest: "33".repeat(32), recoveryOnly: false, minimumCustodyEpoch: "1" };
  const { store, close } = checkpointStore(path, trust);
  try {
    assert.equal(await store.accept(agreed(checkpoint, "22".repeat(32))), true);
    const db = new DatabaseSync(path);
    try {
      db.prepare("UPDATE checkpoints SET digest = ?").run("00".repeat(32));
    } finally {
      db.close();
    }
    const update = agreed({ ...checkpoint, sequence: "5" }, "44".repeat(32));
    await assert.rejects(store.current(), { code: "ReleasePolicyInvalid" });
    await assert.rejects(store.accept(update), { code: "ReleasePolicyInvalid" });
    await assert.rejects(store.current(), { code: "ReleasePolicyInvalid" });
  } finally {
    close();
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
