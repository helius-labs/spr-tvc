import assert from "node:assert/strict";
import { createECDH } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { test } from "node:test";
import { nitroPolicySigningDigest, type NitroPolicy, type NitroTrust } from "../../sdk/src/attestation/nitro-policy.js";
import { signP256Prehash } from "../../sdk/src/crypto/p256.js";
import { encodeLowerHex } from "../../sdk/src/protocol/hex.js";
import { publish } from "../../xtask/nitro-publish.js";

const secrets = [1, 2].map(byte => Buffer.alloc(32, byte));
const trust: NitroTrust = {
  network: "devnet", securityDomainId: "ab".repeat(32), noteSeedCommitment: "de".repeat(32),
  minimumSequence: "1", minimumCustodyEpoch: "1", threshold: 2,
  publications: [
    { bucket: "release-test", account: "000000000001", region: "eu-north-1" },
    { bucket: "release-peer", account: "000000000002", region: "eu-west-1" },
  ],
  keys: secrets.map(secret => {
    const key = createECDH("prime256v1");
    key.setPrivateKey(secret);
    return key.getPublicKey("hex", "uncompressed");
  }),
};
const now = Date.now();
const first: NitroPolicy = {
  version: 1, action: "revoke", network: trust.network, securityDomainId: trust.securityDomainId,
  noteSeedCommitment: trust.noteSeedCommitment, sequence: "1", minimumCustodyEpoch: "1", previousPolicyDigest: null,
  validFromMs: String(now - 1000), expiresAtMs: String(now + 60_000), targets: [],
};

function signed(policy: NitroPolicy) {
  const digest = nitroPolicySigningDigest(policy);
  return JSON.stringify({ policy, signatures: secrets.map((secret, index) => ({
    key: trust.keys[index], signature: encodeLowerHex(signP256Prehash(secret, digest)),
  })) });
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
  const results = await Promise.allSettled(candidates.map(policy => publish(trust, trust.publications[0].bucket, policy, aws)));
  assert.equal(results.filter(result => result.status === "fulfilled").length, 1);
  assert.equal(committed, 1);
  assert.ok(candidates.includes(head));
  await publish(trust, trust.publications[0].bucket, head, aws);
  assert.equal(committed, 1);
});

test("does not publish an activation with an unavailable replica", async context => {
  context.mock.method(globalThis, "fetch", async () => new Response(null, { status: 503 }));
  const activate: NitroPolicy = { ...first, action: "activate", targets: [{
    endpoint: "https://replica.example.com/", releaseId: "candidate", custodyEpoch: "1", executableSha256: "11".repeat(32),
    custodyDigest: "22".repeat(32),
    pcrs: { 0: "12".repeat(48), 1: "23".repeat(48), 2: "34".repeat(48), 3: "45".repeat(48) },
  }] };
  let awsCalls = 0;
  await assert.rejects(publish(trust, trust.publications[0].bucket, signed(activate), async () => {
    awsCalls += 1;
    return { stdout: "{}" };
  }), /BootProofUnverified/);
  assert.equal(awsCalls, 0);
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
  await publish(trust, peer.bucket, signed(first), aws);
  await assert.rejects(publish(trust, "unexpected-bucket", signed(first), aws), /pinned publication buckets/);
  await assert.rejects(publish(trust, peer.bucket, signed({ ...first, minimumCustodyEpoch: "2" }), aws), /ReleasePolicyInvalid/);
  assert.equal(writes, 1);
});

test("checks the second bucket holds the predecessor before advancing the first bucket", async context => {
  const [primary] = trust.publications;
  const second = { ...first, sequence: "2", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(first)) };
  const third = { ...second, sequence: "3", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(second)) };
  context.mock.method(globalThis, "fetch", async () => new Response(signed(first)));
  await assert.rejects(publish(trust, primary.bucket, signed(third), async args => {
    assert.ok(args.includes("get-object"));
    await writeFile(args.at(-1)!, signed(second));
    return { stdout: JSON.stringify({ ETag: '"second"' }) };
  }), /ReleasePolicyInvalid/);
});
