import assert from "node:assert/strict";
import { createECDH } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { test } from "node:test";
import { nitroCustodySigningDigest, nitroPolicySigningDigest, type NitroPolicy, type NitroTrust } from "../../sdk/src/attestation/nitro-policy.js";
import { signP256Prehash } from "../../sdk/src/crypto/p256.js";
import { encodeLowerHex } from "../../sdk/src/protocol/hex.js";
import { bucketPolicy, publish } from "../../xtask/nitro-publish.js";

const secrets = [1, 2, 3, 4].map(byte => Buffer.alloc(32, byte));
const custodySecrets = [5, 6, 7].map(byte => Buffer.alloc(32, byte));
function publicKey(secret: Uint8Array) {
  const key = createECDH("prime256v1");
  key.setPrivateKey(secret);
  return key.getPublicKey("hex", "uncompressed");
}
const keys = secrets.map(publicKey);
const trust: NitroTrust = {
  network: "devnet", securityDomainId: "ab".repeat(32), noteSeedCommitment: "de".repeat(32),
  minimumSequence: "1", minimumCustodyEpoch: "1", threshold: 2,
  publications: [
    { bucket: "release-test", account: "000000000001", region: "eu-north-1" },
    { bucket: "release-peer", account: "000000000002", region: "eu-west-1" },
  ],
  keys: keys.slice(0, 2),
  custodyKeys: custodySecrets.map(publicKey),
};
const now = Date.now();
const first: NitroPolicy = {
  version: 1, action: "revoke", network: trust.network, securityDomainId: trust.securityDomainId,
  noteSeedCommitment: trust.noteSeedCommitment, sequence: "1", minimumCustodyEpoch: "1", previousPolicyDigest: null,
  validFromMs: String(now - 1000), expiresAtMs: String(now + 60_000), targets: [],
};

function signed(policy: NitroPolicy, signers = [0, 1]) {
  const digest = nitroPolicySigningDigest(policy);
  return JSON.stringify({ policy, signatures: signers.map(index => ({
    key: keys[index], signature: encodeLowerHex(signP256Prehash(secrets[index]!, digest)),
  })), custodySignatures: policy.action === "activate" ? custodySecrets.slice(0, 2).map((secret, index) => ({
    key: trust.custodyKeys[index], signature: encodeLowerHex(signP256Prehash(secret, nitroCustodySigningDigest(policy))),
  })) : [] });
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

test("requires custody registration and live attestation before publishing any activation", async context => {
  const fetch = context.mock.method(globalThis, "fetch", async () => new Response(null, { status: 503 }));
  const activate: NitroPolicy = { ...first, action: "activate", targets: [{
    endpoint: "https://replica.example.com/", releaseId: "candidate", custodyEpoch: "1", executableSha256: "11".repeat(32),
    custodyDigest: "22".repeat(32),
    pcrs: { 0: "12".repeat(48), 1: "23".repeat(48), 2: "34".repeat(48), 3: "45".repeat(48) },
  }] };
  const text = signed(activate);
  const bucket = trust.publications[0].bucket;
  await assert.rejects(publish(trust, bucket, text), /requires --custody-trust/);
  const custodyTrust = "/pinned/custody.json";
  let checked = 0;
  let approved = false;
  const run = async (command: string, args: string[]) => {
    assert.equal(command, "python3");
    assert.ok(args[1]?.endsWith("/custody_ledger.py"));
    assert.deepEqual(args.slice(2, 4), [custodyTrust, "check-serving-policy"]);
    assert.equal(await readFile(args.at(-1)!, "utf8"), text);
    assert.equal(fetch.mock.callCount(), 0);
    checked += 1;
    if (!approved) throw new Error("target is absent from the custody ledger");
    return { stdout: "" };
  };
  await assert.rejects(publish(trust, bucket, text, { custodyTrust, run }), /absent from the custody ledger/);
  assert.equal(fetch.mock.callCount(), 0);
  approved = true;
  await assert.rejects(publish(trust, bucket, text, { custodyTrust, run }), /BootProofUnverified/);
  assert.equal(fetch.mock.callCount(), 1);
  assert.equal(checked, 2);
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
  await assert.rejects(publish(trust, peer.bucket, signed({ ...first, minimumCustodyEpoch: "2" }), awsOnly(aws)), /exact signed policy/);
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
  await publish(trust, primary.bucket, dual, runner);
  await assert.rejects(publish(trust, primary.bucket, partial, runner), /new revision/);
  await assert.rejects(publish(trust, mirror.bucket, partial, runner), /exact signed policy/);
  assert.equal(heads.get(mirror.bucket), signed(first));
  await publish(trust, mirror.bucket, dual, runner);
  assert.equal(heads.get(mirror.bucket), heads.get(primary.bucket));

  heads.set(mirror.bucket, partial);
  await assert.rejects(publish(trust, primary.bucket, signed(successor), runner), /same signed predecessor/);
  heads.set(mirror.bucket, dual);
  const rotated = { ...trust, keys: keys.slice(2) };
  const latest = signed(successor, [2, 3]);
  await publish(rotated, primary.bucket, latest, runner);
  await publish(rotated, mirror.bucket, latest, runner);
  assert.equal(heads.get(primary.bucket), latest);
  assert.equal(heads.get(mirror.bucket), latest);
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
