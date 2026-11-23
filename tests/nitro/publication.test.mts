import assert from "node:assert/strict";
import { createECDH, createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test, type TestContext } from "node:test";
import {
  nitroCustodySigningDigest, nitroPolicySigningDigest, nitroPublication, verifyPublishedNitroPolicy,
  type NitroPolicy, type NitroTrust,
} from "../../sdk/src/attestation/nitro-policy.js";
import { signP256Prehash } from "../../sdk/src/crypto/p256.js";
import { CanaryMismatch, type DecryptionCanary } from "../../sdk/src/client/nitro-probe.js";
import { encodeLowerHex } from "../../sdk/src/protocol/hex.js";
import { bucketPolicy, publish, restorePublication, verifyDistributionPins } from "../../xtask/nitro-publish.js";

const secrets = [1, 2, 3, 4].map(byte => Buffer.alloc(32, byte));
const custodySecrets = [5, 6, 7, 8, 9, 10].map(byte => Buffer.alloc(32, byte));
function publicKey(secret: Uint8Array) {
  const key = createECDH("prime256v1");
  key.setPrivateKey(secret);
  return key.getPublicKey("hex", "uncompressed");
}
const keys = secrets.map(publicKey);
const custodyKeys = custodySecrets.map(publicKey);
const trustBase = {
  network: "devnet", securityDomainId: "ab".repeat(32), noteSeedCommitment: "de".repeat(32),
  minimumSequence: "1", minimumCustodyEpoch: "1", threshold: 2,
  publications: [
    { bucket: "release-test", account: "000000000001", region: "eu-north-1" },
    { bucket: "release-peer", account: "000000000002", region: "eu-west-1" },
  ],
  keys: keys.slice(0, 2),
  custodyKeys: custodyKeys.slice(0, 3),
} satisfies Omit<NitroTrust, "minimumPolicyDigest">;
const canaryDigest = "35".repeat(32);
const now = Date.now();
const first: NitroPolicy = {
  version: 1, action: "revoke", recoveryOnly: false, network: trustBase.network, securityDomainId: trustBase.securityDomainId,
  noteSeedCommitment: trustBase.noteSeedCommitment, sequence: "1", minimumCustodyEpoch: "1", previousPolicyDigest: null,
  publications: trustBase.publications,
  validFromMs: String(now - 1000), expiresAtMs: String(now + 60_000), targets: [],
};
const target = {
  endpoint: "https://replica.example.com/", releaseId: "candidate", custodyEpoch: "1", executableSha256: "11".repeat(32),
  custodyDigest: "22".repeat(32),
  pcrs: { 0: "12".repeat(48), 1: "23".repeat(48), 2: "34".repeat(48), 3: "45".repeat(48), 4: "56".repeat(48) },
};

function pins(policy: NitroPolicy): NitroTrust {
  return { ...trustBase, minimumSequence: policy.sequence, minimumPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(policy)) };
}
const trust = pins(first);

function signed(policy: NitroPolicy, signers = [0, 1], custodySigners = [0, 1]) {
  const digest = nitroPolicySigningDigest(policy);
  return JSON.stringify({ policy, signatures: signers.map(index => ({
    key: keys[index], signature: encodeLowerHex(signP256Prehash(secrets[index]!, digest)),
  })), custodySignatures: custodySigners.map(index => ({
    key: custodyKeys[index], signature: encodeLowerHex(signP256Prehash(custodySecrets[index]!, nitroCustodySigningDigest(policy))),
  })) });
}

function awsOnly(aws: (args: string[]) => Promise<{ stdout: string }>) {
  return { run: (command: string, args: string[]) => {
    assert.equal(command, "aws");
    return aws(args);
  } };
}

async function custodyFixture(context: TestContext): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "spr-publication-custody-"));
  context.after(() => rm(directory, { force: true, recursive: true }));
  const path = join(directory, "trust.json");
  await writeFile(path, "{}");
  return path;
}

function policyMetadata(text: string, ETag = '"current"') {
  return { stdout: JSON.stringify({ ETag, VersionId: createHash("sha256").update(text).digest("hex") }) };
}

async function readPolicy(args: string[], text: string, etag?: string) {
  await writeFile(args.at(-1)!, text);
  return policyMetadata(text, etag);
}

function freshProbe(remaining = () => 60_000) {
  return { bootstrapSlots: [1, 2, 3] as const, window: {
    releasePolicyValidFromMs: BigInt(now - 1_000),
    releasePolicyExpiresAtMs: BigInt(now + 120_000),
    policyFreshnessRemainingMs: remaining,
  } };
}

test("restores an exact signed historical policy without replacing a different authenticated head", async context => {
  const previous = { ...first, expiresAtMs: String(now - 1) };
  const next = { ...first, sequence: "2", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(previous)) };
  let backup = signed(previous, [0, 1, 2, 3], [0, 1, 3, 4]);
  const [primary, mirror] = trust.publications;
  const restorePins = pins(previous);
  let selected = primary;
  let witness = mirror;
  let peer = backup;
  context.mock.method(globalThis, "fetch", async (url: URL, options: RequestInit) => {
    assert.ok(url.hostname.startsWith(`${witness.bucket}.s3.`));
    assert.equal(new Headers(options.headers).get("x-amz-expected-bucket-owner"), witness.account);
    return new Response(peer);
  });
  let head = "damaged";
  const held = new Map<string, string>([["damaged", "{}"], ["invalid", ""], ["backup", backup]]);
  let failedResponse = false;
  let race = false;
  let changeWitnessDuringHeadCheck = false;
  let reads = 0;
  let writes = 0;
  const options = awsOnly(async args => {
    assert.equal(args[args.indexOf("--expected-bucket-owner") + 1], selected.account);
    if (args.includes("head-object")) {
      if (changeWitnessDuringHeadCheck && ++reads === 2) peer = signed(next);
      return { stdout: JSON.stringify({ VersionId: head, ContentLength: held.get(head)!.length,
        ETag: race && ++reads > 1 ? '"different-etag"' : '"current-etag"' }) };
    }
    if (args.includes("list-object-versions")) {
      const after = args.includes("--version-id-marker");
      const actualKey = args[args.indexOf("--prefix") + 1]!;
      assert.equal(actualKey, nitroPublication(restorePins, selected).key);
      assert.ok(args.includes("--no-paginate"));
      const entries = after ? ["invalid", "backup"] : [head];
      return { stdout: JSON.stringify({
        Versions: entries.map(id => ({ Key: actualKey, VersionId: id, Size: held.get(id)!.length, IsLatest: id === head })),
        IsTruncated: !after, ...(!after ? { NextKeyMarker: actualKey, NextVersionIdMarker: head } : {}),
      }) };
    }
    if (args.includes("get-object")) {
      const id = args.includes("--version-id") ? args[args.indexOf("--version-id") + 1]! : head;
      await writeFile(args.at(-1)!, held.get(id)!);
      return { stdout: JSON.stringify({ VersionId: id }) };
    }
    assert.ok(args.includes("put-object"));
    assert.equal(args[args.indexOf("--if-match") + 1], '"current-etag"');
    assert.equal(await readFile(args.at(-1)!, "utf8"), backup);
    writes++;
    held.set("restored", backup);
    head = "restored";
    if (failedResponse) throw new Error("lost response");
    return { stdout: JSON.stringify({ VersionId: head }) };
  });
  await assert.rejects(restorePublication(restorePins, primary.bucket, "missing", options), /retained.*missing/);
  held.set("invalid", signed(next));
  await assert.rejects(restorePublication(restorePins, primary.bucket, "backup", options), /different signed policy/);
  held.set("invalid", signed({ ...previous, recoveryOnly: true }));
  await assert.rejects(restorePublication(restorePins, primary.bucket, "backup", options), /different signed policy/);
  const outgoingPolicy = { ...next, recoveryOnly: true };
  const outgoing = signed(outgoingPolicy, [2, 3], [3, 4]);
  const outgoingPins = { ...restorePins, keys: keys.slice(2), custodyKeys: custodyKeys.slice(3) };
  assert.deepEqual(verifyPublishedNitroPolicy([outgoing, outgoing], outgoingPins, BigInt(now)).policy, outgoingPolicy);
  held.set("invalid", outgoing);
  await assert.rejects(restorePublication(restorePins, primary.bucket, "backup", options), /different signed policy/);
  await assert.rejects(restorePublication(restorePins, primary.bucket, "invalid", options), /ReleasePolicyInvalid/);
  held.set("invalid", outgoing.replace(/"signature":"[0-9a-f]+"/, `"signature":"${"00".repeat(64)}"`));
  peer = signed(next);
  await assert.rejects(restorePublication(restorePins, primary.bucket, "backup", options), /ReleasePolicyInvalid/);
  peer = "";
  await assert.rejects(restorePublication(restorePins, primary.bucket, "backup", options), /InvalidCanonicalJson/);
  peer = backup;
  race = true;
  await assert.rejects(restorePublication(restorePins, primary.bucket, "backup", options), /head changed/);
  race = false;
  reads = 0;
  changeWitnessDuringHeadCheck = true;
  await assert.rejects(restorePublication(restorePins, primary.bucket, "backup", options), /ReleasePolicyInvalid/);
  changeWitnessDuringHeadCheck = false;
  peer = backup;
  assert.equal(writes, 0);
  await restorePublication(restorePins, primary.bucket, "backup", options);
  await restorePublication(restorePins, primary.bucket, "backup", options);
  assert.equal(writes, 1);

  selected = mirror;
  witness = primary;
  head = "damaged";
  peer = signed(next);
  failedResponse = true;
  await restorePublication(restorePins, mirror.bucket, "backup", options);
  assert.equal(writes, 2);

  selected = primary;
  witness = mirror;
  failedResponse = false;
  head = "damaged";
  const lagging = { ...next, expiresAtMs: previous.expiresAtMs, recoveryOnly: true };
  const skipped = { ...next, sequence: "3", recoveryOnly: true, minimumCustodyEpoch: "2",
    previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(lagging)) };
  const retained = { ...skipped, sequence: "4", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(skipped)) };
  peer = signed({ ...lagging, recoveryOnly: false });
  held.set("backup", signed({ ...retained, recoveryOnly: false, action: "activate", targets: [{ ...target, custodyEpoch: "2" }] }));
  await assert.rejects(restorePublication(restorePins, primary.bucket, "backup", options), /ReleasePolicyInvalid/);
  held.set("backup", signed(retained));
  peer = signed({ ...lagging, minimumCustodyEpoch: "3" });
  await assert.rejects(restorePublication(restorePins, primary.bucket, "backup", options), /ReleasePolicyInvalid/);
  peer = signed(lagging);
  held.set("backup", signed({ ...retained, recoveryOnly: false }));
  await assert.rejects(restorePublication(restorePins, primary.bucket, "backup", options), /ReleasePolicyInvalid/);
  assert.equal(writes, 2);

  backup = signed(retained);
  held.set("backup", backup);
  await restorePublication(restorePins, primary.bucket, "backup", options);
  assert.equal(writes, 3);
});

test("one conditional publisher wins and replaying the exact policy is idempotent", async context => {
  let head = signed(first);
  context.mock.method(globalThis, "fetch", async () => new Response(signed(first)));
  let etag = '"initial"';
  let committed = 0;
  let arrivals = 0;
  const gate = Promise.withResolvers<void>();
  async function aws(args: string[]) {
    assert.equal(args[args.indexOf("--expected-bucket-owner") + 1], trust.publications[0].account);
    if (args.includes("get-object")) {
      const observed = { head, etag };
      if (++arrivals <= 2) {
        if (arrivals === 2) gate.resolve();
        await gate.promise;
      }
      return readPolicy(args, observed.head, observed.etag);
    }
    assert.ok(args.includes("put-object"));
    const candidate = await readFile(args.at(-1)!, "utf8");
    assert.equal(args[args.indexOf("--cache-control") + 1], "no-store");
    if (args[args.indexOf("--if-match") + 1] !== etag) throw new Error("precondition failed");
    head = candidate;
    etag = '"committed"';
    committed += 1;
    return policyMetadata(head, etag);
  }
  const next = { ...first, sequence: "2", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(first)) };
  const candidates = [signed(next), signed({ ...next, minimumCustodyEpoch: "2" })];
  const results = await Promise.allSettled(candidates.map(policy => publish(trust, trust.publications[0].bucket, policy, awsOnly(aws))));
  assert.equal(results.filter(result => result.status === "fulfilled").length, 1);
  assert.equal(committed, 1);
  assert.ok(candidates.includes(head));
  await publish(trust, trust.publications[0].bucket, head, awsOnly(aws));
  assert.equal(committed, 1);
});

test("confirms a restored head by its current S3 version and exact signed bytes", async context => {
  const text = signed(first);
  const [primary] = trust.publications;
  const key = nitroPublication(trust, primary).key;
  context.mock.method(globalThis, "fetch", async () => new Response(text));
  const writeError = new Error("lost response");
  const readError = new Error("readback unavailable");
  for (const fault of ["missing write", "different version", "different bytes", "missing file", "lost response", "both failed", undefined]) {
    let current = "damaged";
    const objects = new Map([["damaged", "{}"], ["backup", text]]);
    let writes = 0;
    const options = awsOnly(async args => {
      if (args.includes("head-object")) {
        return { stdout: JSON.stringify({ VersionId: current, ContentLength: objects.get(current)!.length, ETag: '"etag"' }) };
      }
      if (args.includes("list-object-versions")) {
        const Versions = [current, "backup"].map(VersionId => ({
          Key: key, VersionId, IsLatest: VersionId === current, Size: objects.get(VersionId)!.length,
        }));
        return { stdout: JSON.stringify({ Versions, IsTruncated: false }) };
      }
      if (args.includes("get-object")) {
        if (fault === "both failed" && !args.includes("--version-id")) throw readError;
        const VersionId = args.includes("--version-id") ? args[args.indexOf("--version-id") + 1]! : current;
        if (fault !== "missing file" || args.includes("--version-id")) {
          await writeFile(args.at(-1)!, objects.get(VersionId)!);
        }
        return { stdout: JSON.stringify({ VersionId }) };
      }
      assert.ok(args.includes("put-object"));
      writes++;
      if (fault !== "missing write") {
        current = fault === "different version" ? "other" : "written";
        objects.set(current, fault === "different bytes" ? "{}" : text);
      }
      if (fault === "lost response" || fault === "both failed") throw writeError;
      return { stdout: JSON.stringify({ VersionId: "written" }) };
    });
    const restore = restorePublication(trust, primary.bucket, "backup", options);
    if (fault === "both failed") {
      await assert.rejects(restore, error => {
        assert.ok(error instanceof AggregateError);
        assert.deepEqual(error.errors, [writeError, readError]);
        return true;
      });
    } else if (fault === "missing file") {
      await assert.rejects(restore, { code: "ENOENT" });
    } else if (fault !== undefined && fault !== "lost response") {
      await assert.rejects(restore, /policy write.*(version|bytes)/);
    } else {
      await restore;
    }
    assert.equal(writes, 1);
  }
});

test("confirms a lost write response only by exact bytes and reports both failures when readback fails", async context => {
  context.mock.method(globalThis, "fetch", async () => new Response(signed(first)));
  const next = { ...first, sequence: "2", previousPolicyDigest: trust.minimumPolicyDigest };
  const text = signed(next);
  const writeError = new Error("write response lost");
  const readError = new Error("readback unavailable");
  for (const outcome of ["committed", "different", "unavailable"]) {
    let wrote = false;
    const runner = awsOnly(async args => {
      if (args.includes("get-object")) {
        if (wrote && outcome === "unavailable") throw readError;
        const head = wrote && outcome === "committed" ? text : signed(first);
        return readPolicy(args, head);
      }
      assert.ok(args.includes("put-object"));
      wrote = true;
      throw writeError;
    });
    const publishNext = publish(trust, trust.publications[0].bucket, text, runner);
    if (outcome === "committed") await publishNext;
    else if (outcome === "different") await assert.rejects(publishNext, writeError);
    else await assert.rejects(publishNext, error => {
      assert.ok(error instanceof Error);
      assert.match(error.message, /write could not be confirmed.*write response lost.*readback unavailable/);
      assert.ok(error instanceof AggregateError);
      assert.deepEqual(error.errors, [writeError, readError]);
      return true;
    });
  }
});

test("confirms a successful publish against the current version and signed bytes", async context => {
  const predecessor = signed(first);
  const next = { ...first, sequence: "2", previousPolicyDigest: trust.minimumPolicyDigest };
  const wanted = signed(next);
  const newer = signed({ ...next, sequence: "3", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(next)) });
  context.mock.method(globalThis, "fetch", async () => new Response(predecessor));
  for (const outcome of ["unchanged", "superseded", "wrong version", "same version", "unversioned", "missing body", "committed"]) {
    let writes = 0;
    const options = awsOnly(async args => {
      if (args.includes("put-object")) {
        writes++;
        assert.ok(args.includes("--if-match"));
        assert.equal(await readFile(args.at(-1)!, "utf8"), wanted);
        return { stdout: JSON.stringify({ VersionId: outcome === "same version" ? "old" : "new" }) };
      }
      assert.ok(args.includes("get-object"));
      const isOld = writes === 0 || outcome === "unchanged";
      const body = isOld ? predecessor : outcome === "superseded" ? newer : wanted;
      let VersionId = "new";
      if (isOld || outcome === "same version") VersionId = "old";
      else if (outcome === "wrong version" || outcome === "superseded") VersionId = "other";
      else if (outcome === "unversioned") VersionId = "null";
      if (writes === 0 || outcome !== "missing body") await writeFile(args.at(-1)!, body);
      return { stdout: JSON.stringify({ VersionId, ETag: '"current"' }) };
    });
    const result = publish(trust, trust.publications[0].bucket, wanted, options);
    if (outcome === "committed") await result;
    else if (outcome === "missing body") await assert.rejects(result, { code: "ENOENT" });
    else if (outcome === "unversioned") await assert.rejects(result, /expected an original S3 policy version/);
    else await assert.rejects(result, /policy write.*(version|bytes)/);
    assert.equal(writes, 1);
  }
});

test("the primary leaves time for the conditional write before policy expiry", async context => {
  const [primary] = trust.publications;
  const predecessor = signed(first);
  let current = now;
  context.mock.method(Date, "now", () => current);
  context.mock.method(globalThis, "fetch", async () => new Response(predecessor));
  const read = awsOnly(async args => {
    assert.ok(args.includes("get-object"));
    return readPolicy(args, predecessor, '"current"');
  });
  const next = { ...first, sequence: "2", previousPolicyDigest: trust.minimumPolicyDigest };
  const activation = signed({ ...next, action: "activate", targets: [target] });
  await assert.rejects(publish(trust, primary.bucket, activation, {
    custodyTrust: await custodyFixture(context),
    async run(command, args) {
      if (command === "python3") return { stdout: JSON.stringify({ custodyKeys: trust.custodyKeys, nextCutover: null, canaryDigest }) };
      return read.run(command, args);
    },
    async probe() { current = now + 30_000; return freshProbe(); },
  }), /policy expires too soon/);
  await assert.rejects(publish(trust, primary.bucket, signed(next), read), /policy expires too soon/);
});

test("requires custody registration, the active roster and live attestation before publishing an activation", async context => {
  const fetch = context.mock.method(globalThis, "fetch", async () => new Response(null, { status: 503 }));
  const activate: NitroPolicy = { ...first, action: "activate", targets: [target] };
  const text = signed(activate);
  const bucket = trust.publications[0].bucket;
  await assert.rejects(publish(pins(activate), bucket, text), /requires --custody-trust/);
  const custodyTrust = await custodyFixture(context);
  let checked = 0;
  let approved = false;
  let roster: { custodyKeys: readonly string[]; nextCutover: string | null; canaryDigest: string } = {
    custodyKeys: custodyKeys.slice(3), nextCutover: null, canaryDigest,
  };
  const run = async (command: string, args: string[]) => {
    assert.equal(command, "python3");
    assert.ok(args[1]?.endsWith("/custody_ledger.py"));
    assert.notEqual(args[2], custodyTrust);
    assert.equal(await readFile(args[2]!, "utf8"), "{}");
    assert.equal(args[3], "check-release-policy");
    assert.equal(await readFile(args.at(-1)!, "utf8"), text);
    assert.equal(fetch.mock.callCount(), 0);
    checked += 1;
    if (!approved) throw new Error("target is absent from the custody ledger");
    return { stdout: JSON.stringify(roster) };
  };
  await assert.rejects(publish(pins(activate), bucket, text, { custodyTrust, run }), /absent from the custody ledger/);
  assert.equal(fetch.mock.callCount(), 0);
  approved = true;
  await assert.rejects(publish(pins(activate), bucket, text, { custodyTrust, run }), /active custody approval roster/);
  roster = { custodyKeys: trust.custodyKeys, nextCutover: String(Math.floor(Date.now() / 1_000) + 10), canaryDigest };
  await assert.rejects(publish(pins(activate), bucket, text, { custodyTrust, run }), /cutover is too close/);
  roster.nextCutover = null;
  await assert.rejects(publish(pins(activate), bucket, text, { custodyTrust, run }), /BootProofUnverified/);
  assert.equal(fetch.mock.callCount(), 1);
  assert.equal(checked, 4);
});

test("qualifies a planned custody transition only after the incoming roster activates", async context => {
  const activate: NitroPolicy = {
    ...first, action: "activate", targets: [target], sequence: "2", previousPolicyDigest: trust.minimumPolicyDigest,
  };
  const incoming = { ...pins(activate), custodyKeys: custodyKeys.slice(3) };
  const text = signed(activate, [0, 1], [0, 1, 3, 4]);
  let attestationRequests = 0;
  context.mock.method(globalThis, "fetch", async (url: URL) => {
    if (url.origin === new URL(target.endpoint).origin) {
      attestationRequests += 1;
      return new Response(null, { status: 503 });
    }
    return new Response(signed(first));
  });
  let activeKeys = trust.custodyKeys;
  const run = async (command: string, args: string[]) => {
    if (command === "python3") return { stdout: JSON.stringify({ custodyKeys: activeKeys, nextCutover: null, canaryDigest }) };
    assert.equal(command, "aws");
    assert.ok(args.includes("get-object"));
    return readPolicy(args, signed(first), '"predecessor"');
  };
  const options = { run, custodyTrust: await custodyFixture(context), nextTrust: incoming };
  await assert.rejects(publish(trust, trust.publications[0].bucket, text, options), /active custody approval roster/);
  assert.equal(attestationRequests, 0);
  activeKeys = [...incoming.custodyKeys].reverse();
  await assert.rejects(publish(trust, trust.publications[0].bucket, text, options), /BootProofUnverified/);
  assert.equal(attestationRequests, 1);
});

test("requires a successful operation probe on every target before writing an activation", async context => {
  const other = { ...target, endpoint: "https://other.example.com/" };
  const activate: NitroPolicy = { ...first, action: "activate", targets: [target, other] };
  const text = signed(activate);
  const pinned = pins(activate);
  const checked: string[] = [];
  const canaries: DecryptionCanary[] = [];
  let failing = true;
  let writes = 0;
  const probe = async (replica: typeof target, supplied: NitroTrust, { canary }: { canary: DecryptionCanary }) => {
    assert.equal(supplied, pinned);
    checked.push(replica.endpoint);
    canaries.push(canary);
    if (replica.endpoint === other.endpoint && failing) throw new Error("operation probe failed");
    return freshProbe();
  };
  const run = async (command: string, args: string[]) => {
    if (command === "python3") return { stdout: JSON.stringify({ custodyKeys: trust.custodyKeys, nextCutover: null, canaryDigest }) };
    assert.equal(command, "aws");
    if (args.includes("get-object")) {
      assert.equal(writes, 1);
      return readPolicy(args, text);
    }
    assert.ok(args.includes("put-object"));
    assert.equal(await readFile(args.at(-1)!, "utf8"), text);
    writes += 1;
    return policyMetadata(text);
  };
  const options = { run, probe, custodyTrust: await custodyFixture(context) };
  await assert.rejects(publish(pinned, trust.publications[0].bucket, text, options), /operation probe failed/);
  assert.equal(writes, 0);
  failing = false;
  await publish(pinned, trust.publications[0].bucket, text, options);
  assert.equal(writes, 1);
  assert.deepEqual(checked, [target.endpoint, other.endpoint, target.endpoint, other.endpoint]);
  assert.equal(canaries[0], canaries[1]);
  assert.equal(canaries[2], canaries[3]);
  assert.notEqual(canaries[0], canaries[2]);
});

test("checks the outgoing boot during fleet replacement and can recover from its outage", async context => {
  const predecessor: NitroPolicy = { ...first, action: "activate", targets: [target] };
  const previous = signed(predecessor);
  const pinned = pins(predecessor);
  const replacement = { ...target, releaseId: "replacement", endpoint: "https://replacement.example.com/" };
  const next: NitroPolicy = {
    ...predecessor, sequence: "2", previousPolicyDigest: pinned.minimumPolicyDigest, targets: [replacement],
  };
  context.mock.method(globalThis, "fetch", async () => new Response(previous));
  let state: "mismatch" | "offline" | "ready" = "mismatch";
  let head = previous;
  let writes = 0;
  const checked: { endpoint: string; canary: DecryptionCanary }[] = [];
  const options = {
    custodyTrust: await custodyFixture(context),
    async run(command: string, args: string[]) {
      if (command === "python3") {
        return { stdout: JSON.stringify({ custodyKeys: pinned.custodyKeys, nextCutover: null, canaryDigest }) };
      }
      assert.equal(command, "aws");
      if (args.includes("get-object")) {
        return readPolicy(args, head, '"predecessor"');
      }
      assert.ok(args.includes("put-object"));
      writes++;
      head = await readFile(args.at(-1)!, "utf8");
      return policyMetadata(head);
    },
    async probe(replica: typeof target, _trust: NitroTrust, { canary }: { canary: DecryptionCanary }) {
      checked.push({ endpoint: replica.endpoint, canary });
      if (replica.endpoint === target.endpoint) {
        if (state === "mismatch") throw new CanaryMismatch();
        if (state === "offline") throw new Error("old replica unavailable");
      }
      return freshProbe();
    },
  };
  const bucket = pinned.publications[0].bucket;
  await assert.rejects(publish(pinned, bucket, signed(next), options), /canary recipient keys differ/);
  assert.equal(writes, 0);
  assert.deepEqual(checked.map(({ endpoint }) => endpoint), [replacement.endpoint, target.endpoint]);
  assert.equal(checked[0]!.canary, checked[1]!.canary);
  state = "offline";
  await publish(pinned, bucket, signed(next), options);
  assert.equal(writes, 1);
  state = "ready";
  head = previous;
  checked.length = 0;
  await publish(pinned, bucket, signed({ ...next, targets: [target, replacement] }), options);
  assert.deepEqual(checked.map(({ endpoint }) => endpoint), [target.endpoint, replacement.endpoint]);
  assert.equal(writes, 2);
});

test("activation rejects an incompatible peer or invalid custody state observed after the probe", async context => {
  const activate: NitroPolicy = {
    ...first, action: "activate", targets: [target], sequence: "2", previousPolicyDigest: trust.minimumPolicyDigest,
  };
  const text = signed(activate);
  const predecessor = signed(first);
  let peer = predecessor;
  let peerStatus = 200;
  let afterCustody: (() => void) | undefined;
  let retired = false;
  let digest = canaryDigest;
  let activeKeys = trust.custodyKeys;
  let cutover: string | null = null;
  context.mock.method(globalThis, "fetch", async () => new Response(peer, { status: peerStatus }));
  let writes = 0;
  const run = async (command: string, args: string[]) => {
    if (command === "python3") {
      assert.equal(await readFile(args.at(-1)!, "utf8"), text);
      if (retired) throw new Error("custody epoch is retired");
      afterCustody?.();
      return { stdout: JSON.stringify({ custodyKeys: activeKeys, nextCutover: cutover, canaryDigest: digest }) };
    }
    assert.equal(command, "aws");
    if (args.includes("get-object")) {
      return readPolicy(args, writes === 0 ? predecessor : text, '"predecessor"');
    }
    writes += 1;
    return policyMetadata(text);
  };
  const options = { run, custodyTrust: await custodyFixture(context) };
  const bucket = trust.publications[0].bucket;
  await assert.rejects(publish(trust, bucket, text, {
    ...options, async probe() { retired = true; return freshProbe(); },
  }), /custody epoch is retired/);
  retired = false;
  await assert.rejects(publish(trust, bucket, text, {
    ...options, async probe() { activeKeys = custodyKeys.slice(3); return freshProbe(); },
  }), /active custody approval roster/);
  activeKeys = trust.custodyKeys;
  await assert.rejects(publish(trust, bucket, text, {
    ...options, async probe() { cutover = String(Math.floor(Date.now() / 1_000) + 10); return freshProbe(); },
  }), /cutover is too close/);
  cutover = null;
  await assert.rejects(publish(trust, bucket, text, {
    ...options, async probe() { digest = "71".repeat(32); return freshProbe(); },
  }), /unchanged custody canary digest/);
  digest = canaryDigest;
  await assert.rejects(publish(trust, bucket, text, {
    ...options, async probe() { peer = signed(first, [1, 0]); return freshProbe(); },
  }), /same signed predecessor/);
  assert.equal(writes, 0);

  const revocation = signed({ ...first, sequence: "2", previousPolicyDigest: trust.minimumPolicyDigest });
  for (const lateChange of [() => { peer = revocation; }, () => { peerStatus = 503; }]) {
    peer = predecessor;
    peerStatus = 200;
    afterCustody = undefined;
    await assert.rejects(publish(trust, bucket, text, {
      ...options, async probe() { afterCustody = lateChange; return freshProbe(); },
    }), /same signed predecessor|HTTP 503/);
    assert.equal(writes, 0);
  }
  peer = predecessor;
  peerStatus = 200;
  afterCustody = undefined;
  await publish(trust, bucket, text, { ...options, async probe() { return freshProbe(); } });
  assert.equal(writes, 1);
});

test("rechecks live replica evidence after the final custody read", async context => {
  const [primary] = trust.publications;
  const activation: NitroPolicy = {
    ...first, action: "activate", targets: [target], sequence: "2", previousPolicyDigest: trust.minimumPolicyDigest,
  };
  const text = signed(activation);
  const predecessor = signed(first);
  let peer = predecessor;
  context.mock.method(globalThis, "fetch", async (url: URL) => new Response(peer, {
    headers: { "x-amz-version-id": url.hostname },
  }));
  let remaining = 0;
  let remainingAfterCustody = 30_000;
  let unavailableBootstrap = false;
  const options = {
    custodyTrust: await custodyFixture(context),
    sourceProfile: "source-read",
    replicaProfile: "replica-read",
    custodyKeyProfiles: "key-profiles.json",
    async run(command: string, args: string[]) {
      if (command === "python3") {
        const profiles = ["--source-profile", "source-read", "--replica-profile", "replica-read",
          "--custody-key-profiles", "key-profiles.json"];
        if (args.includes("--bootstrap-slots")) {
          assert.deepEqual(args.slice(5), [...profiles, "--bootstrap-slots", "[[1,2,3]]"]);
          if (unavailableBootstrap) throw new Error("unavailable attested bootstrap slot");
        } else {
          assert.deepEqual(args.slice(5), profiles);
        }
        remaining = remainingAfterCustody;
        return { stdout: JSON.stringify({ custodyKeys: trust.custodyKeys, nextCutover: null, canaryDigest }) };
      }
      assert.ok(args.includes("get-object"));
      return readPolicy(args, predecessor, '"predecessor"');
    },
    async probe() { remaining = 60_000; return freshProbe(() => remaining); },
  };
  await assert.rejects(publish(trust, primary.bucket, text, options), /replica probe expired or has insufficient time/);
  remainingAfterCustody = 0;
  peer = text;
  await assert.rejects(verifyDistributionPins(pins(activation), options), /replica probe expired or has insufficient time/);
  unavailableBootstrap = true;
  await assert.rejects(verifyDistributionPins(pins(activation), options), /unavailable attested bootstrap slot/);
  peer = predecessor;
  await assert.rejects(publish(trust, primary.bucket, text, options), /unavailable attested bootstrap slot/);
});

test("mirrors the first publisher's policy into only the selected pinned bucket", async context => {
  const [primary, peer] = trust.publications;
  context.mock.method(globalThis, "fetch", async (url: URL, options: RequestInit) => {
    assert.equal(url.hostname, `${primary.bucket}.s3.${primary.region}.amazonaws.com`);
    assert.equal(new Headers(options.headers).get("x-amz-expected-bucket-owner"), primary.account);
    return new Response(signed(first));
  });
  let writes = 0;
  async function aws(args: string[]) {
    assert.equal(args[args.indexOf("--bucket") + 1], peer.bucket);
    assert.equal(args[args.indexOf("--expected-bucket-owner") + 1], peer.account);
    assert.equal(args[args.indexOf("--region") + 1], peer.region);
    if (args.includes("get-object")) {
      if (writes === 0) throw new Error("NoSuchKey");
      return readPolicy(args, signed(first));
    }
    assert.equal(args[args.indexOf("--if-none-match") + 1], "*");
    writes += 1;
    return policyMetadata(signed(first));
  }
  await publish(trust, peer.bucket, signed(first), awsOnly(aws));
  await assert.rejects(publish(trust, "unexpected-bucket", signed(first), awsOnly(aws)), /pinned publication buckets/);
  await assert.rejects(publish(trust, peer.bucket, signed(first, [1, 0]), awsOnly(aws)), /exact signed policy/);
  assert.equal(writes, 1);
});

test("revocation refuses a mirror behind the immediate predecessor", async context => {
  const [primary] = trust.publications;
  const second = { ...first, sequence: "2", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(first)) };
  const third = { ...second, sequence: "3", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(second)) };
  context.mock.method(globalThis, "fetch", async () => new Response(signed(first)));
  await assert.rejects(publish(trust, primary.bucket, signed(third), awsOnly(async args => {
    assert.ok(args.includes("get-object"));
    return readPolicy(args, signed(second), '"second"');
  })), /ReleasePolicyInvalid/);
});

test("an expired primary can catch up the mirror before an emergency revocation", async context => {
  const [primary, mirror] = trust.publications;
  const expired: NitroPolicy = {
    ...first, action: "activate", targets: [target], validFromMs: String(now - 60_000), expiresAtMs: String(now - 1),
  };
  const oldPins = pins(expired);
  const oldText = signed(expired);
  const revoked = signed({ ...first, sequence: "2", previousPolicyDigest: oldPins.minimumPolicyDigest });
  const heads = new Map([[primary.bucket, oldText]]);
  context.mock.method(globalThis, "fetch", async (url: URL) => {
    const text = heads.get(url.hostname.split(".")[0]!);
    return text ? new Response(text) : new Response(null, { status: 404 });
  });
  const writes: string[] = [];
  const runner = awsOnly(async args => {
    const bucket = args[args.indexOf("--bucket") + 1]!;
    if (args.includes("get-object")) {
      const head = heads.get(bucket);
      if (head === undefined) throw new Error("NoSuchKey");
      return readPolicy(args, head, '"current"');
    }
    writes.push(bucket);
    heads.set(bucket, await readFile(args.at(-1)!, "utf8"));
    return policyMetadata(heads.get(bucket)!);
  });

  await assert.rejects(publish(oldPins, primary.bucket, revoked, runner));
  await assert.rejects(publish(oldPins, primary.bucket, oldText, runner), /ReleasePolicyInvalid/);
  await assert.rejects(publish(oldPins, mirror.bucket, signed(expired, [1, 0]), runner), /exact signed policy/);
  await assert.rejects(publish({ ...oldPins, minimumCustodyEpoch: "2" }, mirror.bucket, oldText, runner), /ReleasePolicyInvalid/);
  assert.deepEqual(writes, []);
  await publish(oldPins, mirror.bucket, oldText, runner);
  assert.throws(() => verifyPublishedNitroPolicy([oldText, heads.get(mirror.bucket)!], oldPins, BigInt(now)), /ReleasePolicyInvalid/);
  await publish(oldPins, primary.bucket, revoked, runner);
  await publish(oldPins, mirror.bucket, revoked, runner);
  assert.deepEqual(writes, [mirror.bucket, primary.bucket, mirror.bucket]);
  assert.equal(verifyPublishedNitroPolicy([revoked, heads.get(mirror.bucket)!], oldPins, BigInt(now)).policy.action, "revoke");
});

test("copies the live primary during a custody or replica outage so emergency revocation can advance", async context => {
  const [primary, mirror] = trust.publications;
  const active: NitroPolicy = {
    ...first, action: "activate", targets: [target], sequence: "2", previousPolicyDigest: trust.minimumPolicyDigest,
  };
  const activeText = signed(active);
  const revoked = signed({ ...first, sequence: "3", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(active)) });
  const heads = new Map([[primary.bucket, activeText], [mirror.bucket, signed(first)]]);
  context.mock.method(globalThis, "fetch", async (url: URL) => new Response(heads.get(url.hostname.split(".")[0]!)));
  const writes: string[] = [];
  const runner = {
    ...awsOnly(async args => {
      const bucket = args[args.indexOf("--bucket") + 1]!;
      if (args.includes("get-object")) {
        return readPolicy(args, heads.get(bucket)!, '"prior-etag"');
      }
      assert.ok(args.includes("put-object"));
      assert.equal(args[args.indexOf("--if-match") + 1], '"prior-etag"');
      writes.push(bucket);
      heads.set(bucket, await readFile(args.at(-1)!, "utf8"));
      return policyMetadata(heads.get(bucket)!);
    }),
    probe: async () => assert.fail("mirror and revocation must stay available when probes fail"),
  };
  await assert.rejects(publish(trust, primary.bucket, revoked, runner), /ReleasePolicyInvalid/);
  const differentPrimary = signed({ ...active, targets: [{ ...target, releaseId: "different" }] });
  await assert.rejects(publish(trust, mirror.bucket, differentPrimary, runner), /exact signed policy/);
  heads.set(mirror.bucket, signed({ ...first, minimumCustodyEpoch: "2" }));
  await assert.rejects(publish(trust, mirror.bucket, activeText, runner), /ReleasePolicyInvalid/);
  heads.set(mirror.bucket, signed(first));
  await publish(trust, mirror.bucket, activeText, runner);
  await publish(trust, primary.bucket, revoked, runner);
  await publish(trust, mirror.bucket, revoked, runner);
  assert.deepEqual(writes, [mirror.bucket, primary.bucket, mirror.bucket]);
  assert.equal(verifyPublishedNitroPolicy([heads.get(primary.bucket)!, heads.get(mirror.bucket)!], trust, BigInt(now)).policy.action, "revoke");
});

test("records emergency revocation during a mirror outage and repairs a lagging mirror", async context => {
  const [primary, mirror] = trust.publications;
  const active: NitroPolicy = {
    ...first, action: "activate", targets: [target], sequence: "2", previousPolicyDigest: trust.minimumPolicyDigest,
  };
  const successor = {
    ...first, sequence: "3", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(active)),
  };
  const revoked = signed(successor);
  const activation = signed({ ...successor, action: "activate", targets: [target] });
  const heads = new Map([[primary.bucket, signed(active)], [mirror.bucket, signed(first)]]);
  let mirrorOffline = true;
  context.mock.method(globalThis, "fetch", async (url: URL) => {
    const bucket = url.hostname.split(".")[0]!;
    if (bucket === mirror.bucket && mirrorOffline) return new Response(null, { status: 503 });
    return new Response(heads.get(bucket));
  });
  const writes: string[] = [];
  const options = {
    ...awsOnly(async args => {
      const bucket = args[args.indexOf("--bucket") + 1]!;
      if (args.includes("get-object")) {
        return readPolicy(args, heads.get(bucket)!, '"previous"');
      }
      assert.ok(args.includes("put-object"));
      assert.equal(args[args.indexOf("--if-match") + 1], '"previous"');
      writes.push(bucket);
      heads.set(bucket, await readFile(args.at(-1)!, "utf8"));
      if (bucket === primary.bucket) throw new Error("lost write acknowledgement");
      return policyMetadata(heads.get(bucket)!);
    }),
    probe: async () => assert.fail("a revocation does not contact any enclave"),
  };
  await assert.rejects(publish(trust, primary.bucket, activation, { ...options, custodyTrust: await custodyFixture(context) }), /HTTP 503/);
  await publish(trust, primary.bucket, revoked, options);
  await publish(trust, primary.bucket, revoked, options);
  assert.deepEqual(writes, [primary.bucket]);
  const oldMirror = heads.get(mirror.bucket)!;
  assert.throws(() => verifyPublishedNitroPolicy([revoked, oldMirror], trust, BigInt(now)), /ReleasePolicyInvalid/);
  mirrorOffline = false;
  heads.set(primary.bucket, activation);
  await assert.rejects(publish(trust, mirror.bucket, activation, options), /ReleasePolicyInvalid/);
  heads.set(primary.bucket, revoked);
  for (const previous of [{ ...first, minimumCustodyEpoch: "2" }, { ...first, recoveryOnly: true }]) {
    heads.set(mirror.bucket, signed(previous));
    await assert.rejects(publish(trust, mirror.bucket, revoked, options), /ReleasePolicyInvalid/);
  }
  heads.set(mirror.bucket, oldMirror);
  await publish(trust, mirror.bucket, revoked, options);
  assert.deepEqual(writes, [primary.bucket, mirror.bucket]);
  assert.equal(verifyPublishedNitroPolicy([revoked, heads.get(mirror.bucket)!], trust, BigInt(now)).policy.action, "revoke");
});

test("records a revocation on the mirror during a primary outage only with its immediate predecessor", async context => {
  const [primary, mirror] = trust.publications;
  const active: NitroPolicy = {
    ...first, action: "activate", targets: [target], sequence: "2", previousPolicyDigest: trust.minimumPolicyDigest,
  };
  const predecessor = signed(active);
  const successor = { ...first, sequence: "3", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(active)) };
  const revoked = signed(successor);
  const activation = signed({ ...successor, action: "activate", targets: [target] });
  const heads = new Map([[primary.bucket, predecessor], [mirror.bucket, signed(first)]]);
  let primaryOffline = true;
  context.mock.method(globalThis, "fetch", async (url: URL) => {
    const bucket = url.hostname.split(".")[0]!;
    if (primaryOffline && bucket === primary.bucket) throw new TypeError("failed to fetch");
    return new Response(heads.get(bucket));
  });
  const writes: string[] = [];
  const options = awsOnly(async args => {
    const bucket = args[args.indexOf("--bucket") + 1]!;
    if (args.includes("get-object")) {
      return readPolicy(args, heads.get(bucket)!, '"previous"');
    }
    assert.ok(args.includes("put-object"));
    assert.equal(args[args.indexOf("--if-match") + 1], '"previous"');
    writes.push(bucket);
    heads.set(bucket, await readFile(args.at(-1)!, "utf8"));
    return policyMetadata(heads.get(bucket)!);
  });
  await assert.rejects(publish(trust, mirror.bucket, activation, options), /requires the primary's exact signed policy/);
  await assert.rejects(publish(trust, mirror.bucket, revoked, options), /ReleasePolicyInvalid/);
  heads.set(mirror.bucket, predecessor);
  await assert.rejects(publish(trust, mirror.bucket, signed({ ...successor, expiresAtMs: String(now + 10_000) }), options), /expires too soon/);
  await publish(trust, mirror.bucket, revoked, options);
  assert.deepEqual(writes, [mirror.bucket]);
  primaryOffline = false;
  assert.throws(() => verifyPublishedNitroPolicy([predecessor, revoked], trust, BigInt(now)), /ReleasePolicyInvalid/);
  await assert.rejects(publish(trust, primary.bucket, activation, { ...options, custodyTrust: await custodyFixture(context) }), /same signed predecessor/);
  await publish(trust, primary.bucket, revoked, options);
  assert.deepEqual(writes, [mirror.bucket, primary.bucket]);
  assert.equal(verifyPublishedNitroPolicy([revoked, revoked], trust, BigInt(now)).policy.action, "revoke");
});

test("the mirror rechecks the primary before writing", async context => {
  const original = signed(first);
  let calls = 0;
  context.mock.method(globalThis, "fetch", async () => new Response(++calls === 1 ? original : signed(first, [1, 0])));
  await assert.rejects(publish(trust, trust.publications[1].bucket, original, awsOnly(async args => {
    if (args.includes("get-object")) throw new Error("NoSuchKey");
    assert.fail("the mirror must refuse a changed primary");
  })), /exact signed policy/);
  assert.equal(calls, 2);
});

for (const [primarySequence, mirrorSequence] of [[2, 2], [2, 4], [4, 2]] as const) test(
  `reconciles conflicting publication heads at primary ${primarySequence} and mirror ${mirrorSequence}`, async context => {
  const [primary, mirror] = trust.publications;
  const prior = { ...first, sequence: "2", previousPolicyDigest: trust.minimumPolicyDigest };
  const active: NitroPolicy = { ...prior, action: "activate", targets: [target] };
  let fork = { ...prior, recoveryOnly: true, minimumCustodyEpoch: "2" };
  const heads = new Map([[primary.bucket, signed(active)], [mirror.bucket, signed(first)]]);
  let partitioned = true;
  context.mock.method(globalThis, "fetch", async (url: URL) => {
    const bucket = url.hostname.split(".")[0]!;
    if (partitioned) return new Response(null, { status: 503 });
    return new Response(heads.get(bucket));
  });
  const writes: string[] = [];
  const options = awsOnly(async args => {
    const bucket = args[args.indexOf("--bucket") + 1]!;
    if (args.includes("get-object")) {
      return readPolicy(args, heads.get(bucket)!, '"head"');
    }
    assert.ok(args.includes("put-object"));
    assert.equal(args[args.indexOf("--if-match") + 1], '"head"');
    writes.push(bucket);
    heads.set(bucket, await readFile(args.at(-1)!, "utf8"));
    return policyMetadata(heads.get(bucket)!);
  });

  await publish(trust, mirror.bucket, signed(fork), options);
  for (let sequence = 3; sequence <= mirrorSequence; sequence++) {
    fork = { ...fork, sequence: String(sequence), previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(fork)) };
    await publish(trust, mirror.bucket, signed(fork), options);
  }
  const split = signed(fork);
  let primaryHead = active;
  for (let sequence = 3; sequence <= primarySequence; sequence++) {
    primaryHead = {
      ...prior, sequence: String(sequence), previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(primaryHead)),
    };
    await publish(trust, primary.bucket, signed(primaryHead), options);
  }
  const outageWrites = [
    ...Array<string>(mirrorSequence - 1).fill(mirror.bucket), ...Array<string>(primarySequence - 2).fill(primary.bucket),
  ];
  const nextSequence = Math.max(primarySequence, mirrorSequence) + 1;
  const revocation: NitroPolicy = {
    ...fork, sequence: String(nextSequence), previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(primaryHead)),
  };
  const reconciled = signed(revocation);
  if (nextSequence > primarySequence + 1) {
    await assert.rejects(publish(trust, primary.bucket, reconciled, options), /ReleasePolicyInvalid/);
  }
  partitioned = false;
  const readBoth = () => verifyPublishedNitroPolicy([heads.get(primary.bucket)!, heads.get(mirror.bucket)!], trust, BigInt(now));
  assert.throws(readBoth, /ReleasePolicyInvalid/);
  await assert.rejects(publish(trust, mirror.bucket, reconciled, options), /exact signed policy/);
  const reactivation = signed({
    ...revocation, sequence: String(primarySequence + 1), action: "activate", targets: [{ ...target, custodyEpoch: "2" }],
  });
  await assert.rejects(publish(trust, primary.bucket, reactivation, { ...options, custodyTrust: await custodyFixture(context) }),
    /same signed predecessor/);
  for (const invalid of [
    signed({ ...revocation, minimumCustodyEpoch: "1" }),
    signed({ ...revocation, recoveryOnly: false }),
    signed({ ...revocation, sequence: String(nextSequence + 1) }),
    signed({ ...revocation, previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(fork)) }),
    signed(revocation, [0], [0, 1]),
    signed(revocation, [0, 1], [0]),
  ]) {
    await assert.rejects(publish(trust, primary.bucket, invalid, options), /ReleasePolicyInvalid/);
  }
  assert.deepEqual(writes, outageWrites);
  assert.equal(heads.get(primary.bucket), signed(primaryHead));
  assert.equal(heads.get(mirror.bucket), split);
  heads.set(mirror.bucket, signed(fork, [0], [0, 1]));
  await assert.rejects(publish(trust, primary.bucket, reconciled, options), /ReleasePolicyInvalid/);
  assert.deepEqual(writes, outageWrites);
  heads.set(mirror.bucket, split);
  await publish(trust, primary.bucket, reconciled, options);
  assert.throws(readBoth, /ReleasePolicyInvalid/);
  await publish(trust, mirror.bucket, reconciled, options);
  assert.deepEqual(writes, [...outageWrites, primary.bucket, mirror.bucket]);
  assert.deepEqual(readBoth().policy, revocation);
});

test("publishes a rollover revision with both quorums and mirrors its exact signatures", async context => {
  const [primary, mirror] = trust.publications;
  const heads = new Map([[primary.bucket, signed(first)], [mirror.bucket, signed(first)]]);
  const bridge = { ...first, sequence: "2", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(first)) };
  const dual = signed(bridge, [0, 1, 2, 3]);
  const partial = signed(bridge);
  const successor = { ...bridge, sequence: "3", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(bridge)) };
  context.mock.method(globalThis, "fetch", async (url: URL) => new Response(heads.get(url.hostname.split(".")[0]!)));
  const runner = awsOnly(async args => {
    const bucket = args[args.indexOf("--bucket") + 1]!;
    if (args.includes("get-object")) {
      return readPolicy(args, heads.get(bucket)!, '"current"');
    }
    assert.ok(args.includes("put-object"));
    heads.set(bucket, await readFile(args.at(-1)!, "utf8"));
    return policyMetadata(heads.get(bucket)!);
  });
  const rotated = { ...pins(bridge), keys: keys.slice(2) };
  const transition = { ...runner, nextTrust: rotated };
  await assert.rejects(publish(trust, primary.bucket, dual, runner), /outside the supplied trust bundles/);
  await assert.rejects(publish(trust, primary.bucket, partial, transition), /ReleasePolicyInvalid/);
  await assert.rejects(publish(trust, primary.bucket, signed(bridge, [2, 3]), transition), /ReleasePolicyInvalid/);
  await assert.rejects(publish(trust, primary.bucket, dual, {
    ...runner, nextTrust: { ...rotated, minimumSequence: "1" },
  }), /ReleasePolicyInvalid/);
  assert.equal(heads.get(primary.bucket), signed(first));
  await publish(trust, primary.bucket, dual, transition);
  await assert.rejects(publish(trust, primary.bucket, partial, runner), /new revision/);
  await assert.rejects(publish(trust, mirror.bucket, partial, runner), /exact signed policy/);
  assert.equal(heads.get(mirror.bucket), signed(first));
  await publish(trust, mirror.bucket, dual, transition);
  assert.equal(heads.get(mirror.bucket), heads.get(primary.bucket));

  heads.set(mirror.bucket, partial);
  await publish(trust, mirror.bucket, dual, transition);
  assert.equal(heads.get(mirror.bucket), dual);
  heads.set(primary.bucket, partial);
  await assert.rejects(publish(trust, mirror.bucket, partial, runner), /preserve the existing signers/);
  assert.equal(heads.get(mirror.bucket), dual);
  heads.set(primary.bucket, dual);
  const latest = signed(successor, [2, 3]);
  await publish(rotated, primary.bucket, latest, runner);
  await publish(rotated, mirror.bucket, latest, runner);
  assert.equal(heads.get(primary.bucket), latest);
  assert.equal(heads.get(mirror.bucket), latest);
});

test("repairs a mirrored genesis against its ETag while preserving both signer sets", async context => {
  const [, mirror] = trust.publications;
  let head = signed(first);
  let primary = signed(first, [1, 0], [1, 0, 2]);
  context.mock.method(globalThis, "fetch", async () => new Response(primary));
  const runner = awsOnly(async args => {
    if (args.includes("get-object")) {
      return readPolicy(args, head, '"genesis"');
    }
    assert.equal(args[args.indexOf("--if-match") + 1], '"genesis"');
    head = await readFile(args.at(-1)!, "utf8");
    return policyMetadata(head);
  });
  await publish(trust, mirror.bucket, primary, runner);
  assert.equal(head, primary);
  const repaired = head;
  primary = signed(first);
  await assert.rejects(publish(trust, mirror.bucket, primary, runner), /preserve the existing signers/);
  assert.equal(head, repaired);
});

test("revokes from the same authenticated predecessor when the mirror has extra signers", async context => {
  const [primary, mirror] = trust.publications;
  const active: NitroPolicy = {
    ...first, action: "activate", targets: [target], sequence: "2", previousPolicyDigest: trust.minimumPolicyDigest,
  };
  const prior = signed(active);
  const alternate = signed(active, [0, 1], [0, 1, 2]);
  const next = { ...first, sequence: "3", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(active)) };
  const revoked = signed(next);
  const activation = signed({ ...next, action: "activate", targets: [target] });
  const heads = new Map([[primary.bucket, prior], [mirror.bucket, alternate]]);
  context.mock.method(globalThis, "fetch", async (url: URL) => new Response(heads.get(url.hostname.split(".")[0]!)));
  const runner = awsOnly(async args => {
    const bucket = args[args.indexOf("--bucket") + 1]!;
    if (args.includes("get-object")) {
      return readPolicy(args, heads.get(bucket)!, '"prior"');
    }
    assert.ok(args.includes("put-object"));
    assert.equal(args[args.indexOf("--if-match") + 1], '"prior"');
    heads.set(bucket, await readFile(args.at(-1)!, "utf8"));
    return policyMetadata(heads.get(bucket)!);
  });
  await assert.rejects(publish(trust, mirror.bucket, prior, runner), /preserve the existing signers/);
  await assert.rejects(publish(trust, primary.bucket, activation, { ...runner, custodyTrust: await custodyFixture(context) }), /same signed predecessor/);
  const fork = signed({ ...active, targets: [{ ...target, releaseId: "fork" }] });
  for (const invalid of [signed(active, [0]), fork]) {
    heads.set(mirror.bucket, invalid);
    await assert.rejects(publish(trust, primary.bucket, revoked, runner), /ReleasePolicyInvalid/);
  }
  assert.equal(heads.get(primary.bucket), prior);
  heads.set(mirror.bucket, alternate);
  await publish(trust, primary.bucket, revoked, runner);
  assert.equal(verifyPublishedNitroPolicy([revoked, alternate], trust, BigInt(now)).policy.action, "revoke");
  await publish(trust, mirror.bucket, revoked, runner);
  assert.equal(heads.get(mirror.bucket), revoked);
});

test("an emergency transition authenticates the predecessor without requiring its signers", async context => {
  const [primary] = trust.publications;
  const predecessor = signed(first);
  const successor = { ...first, sequence: "2", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(first)) };
  const incoming = { ...pins(successor), keys: keys.slice(2) };
  const text = signed(successor, [2, 3]);
  context.mock.method(globalThis, "fetch", async () => new Response(predecessor));
  let writes = 0;
  const runner = awsOnly(async args => {
    if (args.includes("get-object")) {
      return readPolicy(args, writes === 0 ? predecessor : text);
    }
    assert.ok(args.includes("put-object"));
    assert.equal(await readFile(args.at(-1)!, "utf8"), text);
    writes += 1;
    return policyMetadata(text);
  });
  await assert.rejects(publish(incoming, primary.bucket, text, runner), /ReleasePolicyInvalid/);
  await assert.rejects(publish(incoming, primary.bucket, text, {
    ...runner, emergencyFrom: { ...trust, minimumCustodyEpoch: "2" },
  }), /ReleasePolicyInvalid/);
  assert.equal(writes, 0);
  await publish(incoming, primary.bucket, text, { ...runner, emergencyFrom: trust });
  assert.equal(writes, 1);
});

test("each wallet policy bucket separates control-plane administration from publishing", () => {
  for (const { bucket, account } of trust.publications) {
    const administrator = `arn:aws:iam::${account}:role/bucket-admin`;
    const publisher = `arn:aws:iam::${account}:role/publisher`;
    const { Statement: statements } = bucketPolicy(trust, bucket, administrator, publisher);
    const guard = statements.find(statement => statement.Sid === "RestrictBucketAdministration");
    assert.equal(guard?.Effect, "Deny");
    assert.equal(guard.Principal, "*");
    assert.equal(guard.Resource, `arn:aws:s3:::${bucket}`);
    assert.deepEqual(guard.Condition, { StringNotEquals: { "aws:PrincipalArn": administrator } });
    for (const action of ["s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutLifecycleConfiguration", "s3:PutBucketCORS"]) {
      assert.ok(guard.Action.includes(action));
    }
    assert.throws(() => bucketPolicy(trust, bucket, publisher, publisher), /separate administrator and publisher/);
    assert.throws(() => bucketPolicy(trust, bucket, administrator.replace(account, "000000000003"), publisher), /publication account/);
  }
});

test("mainnet checks both installed publication buckets before enabling payments or shipping pins", async context => {
  const activation: NitroPolicy = { ...first, network: "mainnet", action: "activate", targets: [target] };
  const mainnet = { ...pins(activation), network: activation.network };
  const text = signed(activation);
  const [primary, mirror] = mainnet.publications;
  let peer = text;
  const versions = new Map(mainnet.publications.map(({ bucket, account }) => [bucket, `version-${account}`]));
  context.mock.method(globalThis, "fetch", async (url: URL) => {
    const version = versions.get(url.hostname.split(".")[0]!);
    return new Response(peer, { headers: version === undefined ? {} : { "x-amz-version-id": version } });
  });
  const inspected = new Set<string>();
  const dir = await mkdtemp(join(tmpdir(), "spr-publication-roles-"));
  context.after(() => rm(dir, { force: true, recursive: true }));
  const custodyTrust = join(dir, "custody.json");
  const role = (account: string, name: string) => `arn:aws:iam::${account}:role/${name}`;
  const publicationRoles = Object.fromEntries(mainnet.publications.map(({ bucket, account }) => [
    bucket, { administratorRole: role(account, "admin"), publisherRole: role(account, "publisher") },
  ]));
  const custody = {
    network: mainnet.network, securityDomainId: mainnet.securityDomainId,
    publications: mainnet.publications, publicationRoles,
  };
  await writeFile(custodyTrust, JSON.stringify(custody));
  let unsafe = "";
  let probes = 0;
  let writes = 0;
  let committed: string | undefined;
  const options = {
    custodyTrust,
    sourceProfile: "source-read", replicaProfile: "replica-read",
    custodyKeyProfiles: "key-profiles.json",
    publicationProfiles: ["primary-read", "mirror-read"],
    async run(command: string, args: string[]) {
      if (command === "python3") {
        const candidate = JSON.parse(await readFile(args[4]!, "utf8"));
        if (candidate.policy.recoveryOnly) assert.ok(!args.includes("--custody-key-profiles"));
        else assert.equal(args[args.indexOf("--custody-key-profiles") + 1], "key-profiles.json");
        return { stdout: JSON.stringify({ custodyKeys: mainnet.custodyKeys, nextCutover: null, canaryDigest }) };
      }
      assert.equal(command, "aws");
      if (args.includes("get-object")) {
        assert.ok(committed);
        assert.ok(!args.includes("--profile"));
        assert.equal(args[args.indexOf("--bucket") + 1], primary.bucket);
        return readPolicy(args, committed);
      }
      if (args.includes("put-object")) {
        assert.ok(!args.includes("--profile"));
        assert.equal(args[args.indexOf("--bucket") + 1], primary.bucket);
        writes++;
        committed = await readFile(args.at(-1)!, "utf8");
        return policyMetadata(committed);
      }
      assert.ok(probes > 0);
      const bucket = args[args.indexOf("--bucket") + 1];
      const pin = bucket === primary.bucket ? primary : mirror;
      const correct = pin === primary ? "primary-read" : "mirror-read";
      assert.equal(bucket, pin.bucket);
      assert.equal(args[args.indexOf("--profile") + 1], correct);
      assert.equal(args[args.indexOf("--expected-bucket-owner") + 1], pin.account);
      inspected.add(bucket);
      const hazard = pin === mirror ? unsafe : undefined;
      if (args.includes("get-bucket-lifecycle-configuration")) {
        assert.equal(args[args.indexOf("--cli-error-format") + 1], "json");
        if (hazard === "lifecycle") return { stdout: '{"Rules":[{"Status":"Enabled"}]}' };
        const Code = hazard === "permission" ? "AccessDenied" : "NoSuchLifecycleConfiguration";
        throw Object.assign(new Error(Code), { stderr: JSON.stringify({ Code }) });
      }
      if (args.includes("get-bucket-versioning")) {
        return { stdout: JSON.stringify({ Status: hazard === "versioning" ? "Suspended" : "Enabled" }) };
      }
      if (args.includes("get-bucket-ownership-controls")) {
        const ObjectOwnership = hazard === "ownership" ? "ObjectWriter" : "BucketOwnerEnforced";
        return { stdout: JSON.stringify({ OwnershipControls: { Rules: [{ ObjectOwnership }] } }) };
      }
      if (args.includes("get-bucket-cors")) {
        return { stdout: JSON.stringify({ CORSRules: [{
          AllowedOrigins: hazard === "cors-origin" ? [] : ["https://wallet.example"],
          AllowedMethods: [hazard === "cors-method" ? "HEAD" : "GET"],
          AllowedHeaders: [hazard === "cors-header" ? "content-type" : pin === primary ? "x-amz-*" : "x-amz-expected-bucket-owner"],
        }] }) };
      }
      assert.ok(args.includes("get-bucket-policy"));
      const policy = bucketPolicy(
        mainnet, pin.bucket,
        role(pin.account, hazard === "administrator" ? "different-admin" : "admin"),
        role(pin.account, hazard === "publisher" ? "different-publisher" : "publisher"),
      );
      if (hazard === "policy") policy.Statement.pop();
      return { stdout: JSON.stringify({ Policy: JSON.stringify(policy) }) };
    },
    async probe() { probes++; return freshProbe(); },
  };
  const missingProfiles = { custodyTrust: options.custodyTrust, run: options.run, probe: options.probe };
  await assert.rejects(publish(mainnet, primary.bucket, text, missingProfiles), /provide --publication-profile twice/);
  await assert.rejects(verifyDistributionPins(mainnet, missingProfiles), /provide --publication-profile twice/);
  for (const [invalid, message] of [
    [{ ...custody, publicationRoles: undefined }, /requires role pins for both publication buckets/],
    [{ ...custody, network: "devnet" }, /must pin the wallet's publication domain and buckets/],
    [{ ...custody, publications: [mirror, primary] }, /must pin the wallet's publication domain and buckets/],
    [{ ...custody, publicationRoles: { ...publicationRoles, [mirror.bucket]: publicationRoles[primary.bucket] } },
      /use separate administrator and publisher roles in the publication account/],
  ] as const) {
    await writeFile(custodyTrust, JSON.stringify(invalid));
    await assert.rejects(publish(mainnet, primary.bucket, text, options), message);
    await assert.rejects(verifyDistributionPins(mainnet, options), message);
  }
  assert.equal(probes, 0);
  await writeFile(custodyTrust, JSON.stringify(custody));
  for (const [hazard, message] of [
    ["lifecycle", /must have no lifecycle/], ["permission", /AccessDenied/], ["versioning", /requires versioning/],
    ["ownership", /requires bucket-owner-enforced ownership/],
    ["cors-method", /requires CORS for wallet policy reads/], ["cors-header", /requires CORS for wallet policy reads/],
    ["cors-origin", /requires CORS for wallet policy reads/],
    ["policy", /differs from the custody-pinned bucket policy/],
    ["administrator", /differs from the custody-pinned bucket policy/],
    ["publisher", /differs from the custody-pinned bucket policy/],
  ] as const) {
    unsafe = hazard;
    await assert.rejects(publish(mainnet, primary.bucket, text, options), message);
    await assert.rejects(verifyDistributionPins(mainnet, options), message);
  }
  assert.equal(writes, 0);
  assert.deepEqual(inspected, new Set([primary.bucket, mirror.bucket]));
  unsafe = "";
  versions.delete(mirror.bucket);
  await assert.rejects(verifyDistributionPins(mainnet, options), /expected an original S3 policy version/);
  versions.set(mirror.bucket, "null");
  await assert.rejects(verifyDistributionPins(mainnet, options), /expected an original S3 policy version/);
  versions.set(mirror.bucket, `version-${mirror.account}`);
  const changedCustody = {
    ...custody,
    publicationRoles: {
      ...publicationRoles,
      [primary.bucket]: { ...publicationRoles[primary.bucket], administratorRole: role(primary.account, "new-admin") },
    },
  };
  let snapshotChecks = 0;
  const reviewedCustody = JSON.stringify(custody);
  const changedDuringProbe = {
    ...options,
    async run(command: string, args: string[]) {
      if (command === "python3") {
        assert.notEqual(args[2], custodyTrust);
        assert.equal(await readFile(args[2]!, "utf8"), reviewedCustody);
        snapshotChecks++;
      }
      return options.run(command, args);
    },
    async probe() {
      await writeFile(custodyTrust, JSON.stringify(changedCustody));
      return options.probe();
    },
  };
  await assert.rejects(verifyDistributionPins(mainnet, changedDuringProbe), /custody trust changed/);
  assert.equal(snapshotChecks, 2);
  await writeFile(custodyTrust, reviewedCustody);
  await assert.rejects(publish(mainnet, primary.bucket, text, changedDuringProbe), /custody trust changed/);
  assert.equal(snapshotChecks, 4);
  assert.equal(writes, 0);
  await writeFile(custodyTrust, reviewedCustody);
  for (const { bucket, account } of mainnet.publications) {
    await assert.rejects(verifyDistributionPins(mainnet, {
      ...options, async probe() {
        versions.set(bucket, "new-version-with-the-same-bytes");
        return options.probe();
      },
    }), /S3 policy version changed during wallet trust verification/);
    versions.set(bucket, `version-${account}`);
  }
  await publish(mainnet, primary.bucket, text, options);
  const verified = await verifyDistributionPins(mainnet, options);
  assert.equal(verified.sequence, "1");
  assert.deepEqual(verified.publicationVersions, [
    { bucket: primary.bucket, versionId: `version-${primary.account}` },
    { bucket: mirror.bucket, versionId: `version-${mirror.account}` },
  ]);
  assert.equal(writes, 1);

  inspected.clear();
  await writeFile(custodyTrust, JSON.stringify({ ...custody, publicationRoles: undefined }));
  const recovery = { ...activation, recoveryOnly: true };
  peer = signed(recovery);
  const recoveryPins = { ...pins(recovery), network: recovery.network, recoveryOnly: true };
  await publish(recoveryPins, primary.bucket, peer, missingProfiles);
  const recoveryCheckpoint = await verifyDistributionPins(recoveryPins, missingProfiles);
  assert.equal(recoveryCheckpoint.recoveryOnly, true);
  assert.deepEqual(recoveryCheckpoint.publicationVersions, verified.publicationVersions);
  await assert.rejects(verifyDistributionPins(recoveryPins, {
    ...missingProfiles, async probe() {
      versions.set(mirror.bucket, "different-recovery-version");
      return options.probe();
    },
  }), /S3 policy version changed during wallet trust verification/);
  assert.equal(inspected.size, 0);
});

test("ships only the exact current policy agreed by the two pinned buckets", async context => {
  let current = { ...first, sequence: "2", previousPolicyDigest: trust.minimumPolicyDigest };
  let peer = first;
  let mirrorEnvelope: string | undefined;
  let mirrorVersion: string | undefined = "mirror-revocation";
  context.mock.method(globalThis, "fetch", async (url: URL, options: RequestInit) => {
    const isPrimary = url.hostname.startsWith(trust.publications[0].bucket + ".");
    const account = trust.publications[isPrimary ? 0 : 1].account;
    assert.equal(new Headers(options.headers).get("x-amz-expected-bucket-owner"), account);
    const version = isPrimary ? "primary-revocation" : mirrorVersion;
    return new Response(isPrimary ? signed(current) : mirrorEnvelope ?? signed(peer), {
      headers: version === undefined ? {} : { "x-amz-version-id": version },
    });
  });
  await assert.rejects(verifyDistributionPins(pins(current)), /same signed policy file/);
  peer = current;
  mirrorEnvelope = signed(current, [0, 1, 2, 3]);
  await assert.rejects(verifyDistributionPins(pins(current)), /same signed policy file/);
  mirrorEnvelope = "\uFEFF" + signed(current);
  await assert.rejects(verifyDistributionPins(pins(current)), /InvalidCanonicalJson/);
  mirrorEnvelope = undefined;
  await assert.rejects(verifyDistributionPins(trust), /match the current policy/);
  await assert.rejects(verifyDistributionPins({ ...pins(current), minimumPolicyDigest: "99".repeat(32) }), /ReleasePolicyInvalid/);
  for (const version of [undefined, "null"]) {
    mirrorVersion = version;
    await assert.rejects(verifyDistributionPins(pins(current)), /expected an original S3 policy version/);
  }
  mirrorVersion = "mirror-revocation";
  const verified = await verifyDistributionPins(pins(current));
  assert.equal(verified.sequence, current.sequence);
  assert.deepEqual(verified.publicationVersions, [
    { bucket: trust.publications[0].bucket, versionId: "primary-revocation" },
    { bucket: trust.publications[1].bucket, versionId: "mirror-revocation" },
  ]);
  current = peer = { ...current, minimumCustodyEpoch: "2", recoveryOnly: true };
  await assert.rejects(verifyDistributionPins(pins(current)), /match the current policy/);
  assert.equal((await verifyDistributionPins({ ...pins(current), minimumCustodyEpoch: "2", recoveryOnly: true })).sequence, "2");
});

test("wallet activation pins require the active custody roster and a stable published envelope", async context => {
  const activate: NitroPolicy = {
    ...first, action: "activate", targets: [target], sequence: "2", previousPolicyDigest: trust.minimumPolicyDigest,
  };
  const text = signed(activate, [0, 1], [0, 1, 3, 4]);
  const incoming = { ...pins(activate), custodyKeys: custodyKeys.slice(3) };
  let head = text;
  context.mock.method(globalThis, "fetch", async (url: URL) => new Response(head, {
    headers: { "x-amz-version-id": url.hostname },
  }));
  const custodyTrust = await custodyFixture(context);
  let nextCutover: string | null = null;
  let changedEnvelope: string | undefined;
  let retired = false;
  const run = async (command: string, args: string[]) => {
    assert.equal(command, "python3");
    assert.notEqual(args[2], custodyTrust);
    assert.equal(await readFile(args[2]!, "utf8"), "{}");
    assert.equal(args[3], "check-release-policy");
    assert.equal(await readFile(args.at(-1)!, "utf8"), text);
    if (retired) throw new Error("custody epoch is retired");
    if (changedEnvelope) head = changedEnvelope;
    return { stdout: JSON.stringify({ custodyKeys: incoming.custodyKeys, nextCutover, canaryDigest }) };
  };
  let failing = false;
  const probe = async (replica: typeof target) => {
    assert.deepEqual(replica, target);
    if (failing) throw new Error("operation probe failed");
    return freshProbe();
  };
  const options = { custodyTrust, run, probe };
  await assert.rejects(verifyDistributionPins(incoming), /requires --custody-trust/);
  await assert.rejects(verifyDistributionPins(pins(activate), options), /active custody approval roster/);
  nextCutover = String(Math.floor(Date.now() / 1_000));
  await assert.rejects(verifyDistributionPins(incoming, options), /roster changed/);
  nextCutover = null;
  failing = true;
  await assert.rejects(verifyDistributionPins(incoming, options), /operation probe failed/);
  failing = false;
  assert.equal((await verifyDistributionPins(incoming, options)).sequence, "2");
  await assert.rejects(verifyDistributionPins(incoming, {
    ...options, async probe() { retired = true; return freshProbe(); },
  }), /custody epoch is retired/);
  retired = false;
  changedEnvelope = signed(activate, [1, 0], [0, 1, 3, 4]);
  await assert.rejects(verifyDistributionPins(incoming, options), /signed policy changed/);
});
