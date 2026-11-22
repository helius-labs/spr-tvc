import assert from "node:assert/strict";
import { createECDH } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { test } from "node:test";
import {
  nitroCustodySigningDigest, nitroPolicySigningDigest, verifyPublishedNitroPolicy, type NitroPolicy, type NitroTrust,
} from "../../sdk/src/attestation/nitro-policy.js";
import { signP256Prehash } from "../../sdk/src/crypto/p256.js";
import { encodeLowerHex } from "../../sdk/src/protocol/hex.js";
import { bucketPolicy, publish, verifyDistributionPins } from "../../xtask/nitro-publish.js";

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
      await writeFile(args.at(-1)!, observed.head);
      return { stdout: JSON.stringify({ ETag: observed.etag }) };
    }
    assert.ok(args.includes("put-object"));
    const candidate = await readFile(args.at(-1)!, "utf8");
    assert.equal(args[args.indexOf("--cache-control") + 1], "no-store");
    if (args[args.indexOf("--if-match") + 1] !== etag) throw new Error("precondition failed");
    head = candidate;
    etag = '"committed"';
    committed += 1;
    return { stdout: "{}" };
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

test("requires custody registration, the active roster and live attestation before publishing an activation", async context => {
  const fetch = context.mock.method(globalThis, "fetch", async () => new Response(null, { status: 503 }));
  const activate: NitroPolicy = { ...first, action: "activate", targets: [target] };
  const text = signed(activate);
  const bucket = trust.publications[0].bucket;
  await assert.rejects(publish(pins(activate), bucket, text), /requires --custody-trust/);
  const custodyTrust = "/pinned/custody.json";
  let checked = 0;
  let approved = false;
  let roster: { custodyKeys: readonly string[]; nextCutover: string | null } = {
    custodyKeys: custodyKeys.slice(3), nextCutover: null,
  };
  const run = async (command: string, args: string[]) => {
    assert.equal(command, "python3");
    assert.ok(args[1]?.endsWith("/custody_ledger.py"));
    assert.deepEqual(args.slice(2, 4), [custodyTrust, "check-release-policy"]);
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
  roster = { custodyKeys: trust.custodyKeys, nextCutover: String(Math.floor(Date.now() / 1_000) + 10) };
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
    if (command === "python3") return { stdout: JSON.stringify({ custodyKeys: activeKeys, nextCutover: null }) };
    assert.equal(command, "aws");
    assert.ok(args.includes("get-object"));
    await writeFile(args.at(-1)!, signed(first));
    return { stdout: JSON.stringify({ ETag: '"predecessor"' }) };
  };
  const options = { run, custodyTrust: "/pinned/custody.json", nextTrust: incoming };
  await assert.rejects(publish(trust, trust.publications[0].bucket, text, options), /active custody approval roster/);
  assert.equal(attestationRequests, 0);
  activeKeys = [...incoming.custodyKeys].reverse();
  await assert.rejects(publish(trust, trust.publications[0].bucket, text, options), /BootProofUnverified/);
  assert.equal(attestationRequests, 1);
});

test("requires a successful operation probe on every target before writing an activation", async () => {
  const other = { ...target, endpoint: "https://other.example.com/" };
  const activate: NitroPolicy = { ...first, action: "activate", targets: [target, other] };
  const text = signed(activate);
  const pinned = pins(activate);
  const checked: string[] = [];
  let failing = true;
  let writes = 0;
  const probe = async (replica: typeof target, supplied: NitroTrust) => {
    assert.equal(supplied, pinned);
    checked.push(replica.endpoint);
    if (replica.endpoint === other.endpoint && failing) throw new Error("operation probe failed");
  };
  const run = async (command: string, args: string[]) => {
    if (command === "python3") return { stdout: JSON.stringify({ custodyKeys: trust.custodyKeys, nextCutover: null }) };
    assert.equal(command, "aws");
    assert.ok(args.includes("put-object"));
    assert.equal(await readFile(args.at(-1)!, "utf8"), text);
    writes += 1;
    return { stdout: "{}" };
  };
  const options = { run, probe, custodyTrust: "/pinned/custody.json" };
  await assert.rejects(publish(pinned, trust.publications[0].bucket, text, options), /operation probe failed/);
  assert.equal(writes, 0);
  failing = false;
  await publish(pinned, trust.publications[0].bucket, text, options);
  assert.equal(writes, 1);
  assert.deepEqual(checked, [target.endpoint, other.endpoint, target.endpoint, other.endpoint]);
});

test("activation rejects an incompatible peer or invalid custody state observed after the probe", async context => {
  const activate: NitroPolicy = {
    ...first, action: "activate", targets: [target], sequence: "2", previousPolicyDigest: trust.minimumPolicyDigest,
  };
  const text = signed(activate);
  const predecessor = signed(first);
  let peer = predecessor;
  let retired = false;
  let activeKeys = trust.custodyKeys;
  let cutover: string | null = null;
  context.mock.method(globalThis, "fetch", async () => new Response(peer));
  let writes = 0;
  const run = async (command: string, args: string[]) => {
    if (command === "python3") {
      assert.equal(await readFile(args.at(-1)!, "utf8"), text);
      if (retired) throw new Error("custody epoch is retired");
      return { stdout: JSON.stringify({ custodyKeys: activeKeys, nextCutover: cutover }) };
    }
    assert.equal(command, "aws");
    if (args.includes("get-object")) {
      await writeFile(args.at(-1)!, predecessor);
      return { stdout: JSON.stringify({ ETag: '"predecessor"' }) };
    }
    writes += 1;
    return { stdout: "{}" };
  };
  const options = { run, custodyTrust: "/pinned/custody.json" };
  const bucket = trust.publications[0].bucket;
  await assert.rejects(publish(trust, bucket, text, {
    ...options, async probe() { retired = true; },
  }), /custody epoch is retired/);
  retired = false;
  await assert.rejects(publish(trust, bucket, text, {
    ...options, async probe() { activeKeys = custodyKeys.slice(3); },
  }), /active custody approval roster/);
  activeKeys = trust.custodyKeys;
  await assert.rejects(publish(trust, bucket, text, {
    ...options, async probe() { cutover = String(Math.floor(Date.now() / 1_000) + 10); },
  }), /cutover is too close/);
  cutover = null;
  await assert.rejects(publish(trust, bucket, text, {
    ...options, async probe() { peer = signed(first, [1, 0]); },
  }), /same signed predecessor/);
  assert.equal(writes, 0);
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
    assert.equal(args[args.indexOf("--if-none-match") + 1], "*");
    writes += 1;
    return { stdout: "{}" };
  }
  await publish(trust, peer.bucket, signed(first), awsOnly(aws));
  await assert.rejects(publish(trust, "unexpected-bucket", signed(first), awsOnly(aws)), /pinned publication buckets/);
  await assert.rejects(publish(trust, peer.bucket, signed(first, [1, 0]), awsOnly(aws)), /exact signed policy/);
  assert.equal(writes, 1);
});

test("checks the second bucket holds the predecessor before advancing the first bucket", async context => {
  const [primary] = trust.publications;
  const second = { ...first, sequence: "2", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(first)) };
  const third = { ...second, sequence: "3", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(second)) };
  context.mock.method(globalThis, "fetch", async () => new Response(signed(first)));
  await assert.rejects(publish(trust, primary.bucket, signed(third), awsOnly(async args => {
    assert.ok(args.includes("get-object"));
    await writeFile(args.at(-1)!, signed(second));
    return { stdout: JSON.stringify({ ETag: '"second"' }) };
  })), /same signed predecessor/);
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
      await writeFile(args.at(-1)!, heads.get(bucket)!);
      return { stdout: JSON.stringify({ ETag: '"current"' }) };
    }
    writes.push(bucket);
    heads.set(bucket, await readFile(args.at(-1)!, "utf8"));
    return { stdout: "{}" };
  });

  await assert.rejects(publish(oldPins, primary.bucket, revoked, runner));
  await assert.rejects(publish(oldPins, primary.bucket, oldText, runner), /ReleasePolicyInvalid/);
  await assert.rejects(publish(oldPins, mirror.bucket, signed(expired, [1, 0]), runner), /exact signed policy/);
  await assert.rejects(publish({ ...oldPins, minimumCustodyEpoch: "2" }, mirror.bucket, oldText, runner), /ReleasePolicyInvalid/);
  const live = { ...expired, expiresAtMs: first.expiresAtMs };
  const liveText = signed(live);
  heads.set(primary.bucket, liveText);
  await assert.rejects(publish(pins(live), mirror.bucket, liveText, runner), /requires --custody-trust/);
  heads.set(primary.bucket, oldText);
  assert.deepEqual(writes, []);
  await publish(oldPins, mirror.bucket, oldText, runner);
  assert.throws(() => verifyPublishedNitroPolicy([oldText, heads.get(mirror.bucket)!], oldPins, BigInt(now)), /ReleasePolicyInvalid/);
  await publish(oldPins, primary.bucket, revoked, runner);
  await publish(oldPins, mirror.bucket, revoked, runner);
  assert.deepEqual(writes, [mirror.bucket, primary.bucket, mirror.bucket]);
  assert.equal(verifyPublishedNitroPolicy([revoked, heads.get(mirror.bucket)!], oldPins, BigInt(now)).policy.action, "revoke");
});

test("the mirror rechecks the primary before writing", async context => {
  const original = signed(first);
  let calls = 0;
  context.mock.method(globalThis, "fetch", async () => new Response(++calls === 1 ? original : signed(first, [1, 0])));
  await assert.rejects(publish(trust, trust.publications[1].bucket, original, awsOnly(async () => {
    assert.fail("the mirror must refuse a changed primary");
  })), /exact signed policy/);
  assert.equal(calls, 2);
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
      await writeFile(args.at(-1)!, heads.get(bucket)!);
      return { stdout: JSON.stringify({ ETag: '"current"' }) };
    }
    assert.ok(args.includes("put-object"));
    heads.set(bucket, await readFile(args.at(-1)!, "utf8"));
    return { stdout: "{}" };
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
  await assert.rejects(publish(trust, primary.bucket, signed(successor), runner), /same signed predecessor/);
  heads.set(mirror.bucket, dual);
  const latest = signed(successor, [2, 3]);
  await publish(rotated, primary.bucket, latest, runner);
  await publish(rotated, mirror.bucket, latest, runner);
  assert.equal(heads.get(primary.bucket), latest);
  assert.equal(heads.get(mirror.bucket), latest);
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
      await writeFile(args.at(-1)!, predecessor);
      return { stdout: JSON.stringify({ ETag: '"current"' }) };
    }
    assert.ok(args.includes("put-object"));
    assert.equal(await readFile(args.at(-1)!, "utf8"), text);
    writes += 1;
    return { stdout: "{}" };
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

test("ships only the exact current policy agreed by the two pinned buckets", async context => {
  let current = { ...first, sequence: "2", previousPolicyDigest: trust.minimumPolicyDigest };
  let peer = first;
  let mirrorEnvelope: string | undefined;
  context.mock.method(globalThis, "fetch", async (url: URL, options: RequestInit) => {
    const isPrimary = url.hostname.startsWith(trust.publications[0].bucket + ".");
    const account = trust.publications[isPrimary ? 0 : 1].account;
    assert.equal(new Headers(options.headers).get("x-amz-expected-bucket-owner"), account);
    return new Response(isPrimary ? signed(current) : mirrorEnvelope ?? signed(peer));
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
  assert.equal((await verifyDistributionPins(pins(current))).sequence, current.sequence);
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
  context.mock.method(globalThis, "fetch", async () => new Response(head));
  const custodyTrust = "/pinned/custody.json";
  let nextCutover: string | null = null;
  let changedEnvelope: string | undefined;
  let retired = false;
  const run = async (command: string, args: string[]) => {
    assert.equal(command, "python3");
    assert.deepEqual(args.slice(2, 4), [custodyTrust, "check-release-policy"]);
    assert.equal(await readFile(args.at(-1)!, "utf8"), text);
    if (retired) throw new Error("custody epoch is retired");
    if (changedEnvelope) head = changedEnvelope;
    return { stdout: JSON.stringify({ custodyKeys: incoming.custodyKeys, nextCutover }) };
  };
  let failing = false;
  const probe = async (replica: typeof target) => {
    assert.deepEqual(replica, target);
    if (failing) throw new Error("operation probe failed");
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
    ...options, async probe() { retired = true; },
  }), /custody epoch is retired/);
  retired = false;
  changedEnvelope = signed(activate, [1, 0], [0, 1, 3, 4]);
  await assert.rejects(verifyDistributionPins(incoming, options), /signed policy changed/);
});
