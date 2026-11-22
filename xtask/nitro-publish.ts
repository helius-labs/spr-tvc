import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs, promisify } from "node:util";
import {
  nextNitroPublication, nitroPublication, requireNitroTrustTransition, validateNitroTrust,
  verifyNitroMirrorPolicy, verifyNitroPolicy, type NitroTarget, type NitroTrust,
} from "../sdk/src/attestation/nitro-policy.js";
import { readNitroPolicy, readPublishedNitroPolicy } from "../sdk/src/attestation/nitro-publication.js";
import { probeNitroTarget } from "../sdk/src/client/nitro-probe.js";
import { remainingReleasePolicyMs } from "../sdk/src/connection/operations.js";
import { decodeDecimalU64 } from "../sdk/src/protocol/decimal.js";
import { parseStrictJson } from "../sdk/src/protocol/json.js";

const execute = promisify(execFile);
const MAX_BYTES = 32_768;
const WRITE_MARGIN_MS = 30_000n;
const custodyLedger = fileURLToPath(new URL("../enclave/deploy/nitro/custody_ledger.py", import.meta.url));
type Run = (command: string, args: string[], timeout: number) => Promise<{ stdout: string }>;
const runCommand: Run = (command, args, timeout) => execute(command, args, {
  timeout, maxBuffer: 64 * 1024,
  env: { ...process.env, AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: "true" },
});

type PublicationOptions = {
  custodyTrust?: string;
  nextTrust?: NitroTrust;
  emergencyFrom?: NitroTrust;
  run?: Run;
  probe?: (target: NitroTarget, trust: NitroTrust) => Promise<ReplicaProbe>;
};

type ReplicaProbe = Pick<Awaited<ReturnType<typeof probeNitroTarget>>, "window">;

function requireFreshProbes(probes: readonly ReplicaProbe[], now: bigint, margin = 0): void {
  if (probes.some(({ window }) => !(remainingReleasePolicyMs(window, now) > margin))) {
    throw new Error("replica probe expired or has insufficient time remaining");
  }
}

async function readPolicy(path: string): Promise<string> {
  const file = await open(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    if (!(await file.stat()).isFile()) throw new Error("expected a regular policy or trust file");
    const buffer = Buffer.alloc(MAX_BYTES + 1);
    let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await file.read(buffer, size, buffer.length - size, size);
      if (bytesRead === 0) break;
      size += bytesRead;
    }
    if (size > MAX_BYTES) throw new Error("JSON document exceeds 32 KiB");
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buffer.subarray(0, size));
  } finally {
    await file.close();
  }
}

function publicationFor(trust: NitroTrust, bucket: string) {
  const publication = trust.publications.find(candidate => candidate.bucket === bucket);
  if (!publication) throw new Error("expected one of the pinned publication buckets");
  return nitroPublication(trust, publication);
}

function requireCustodyWriteWindow(nextCutover: bigint | undefined, now: bigint): void {
  if (nextCutover !== undefined && now + WRITE_MARGIN_MS >= nextCutover) {
    throw new Error("custody approval cutover is too close for publication");
  }
}

async function checkActivationRoster(candidate: string, custodyTrust: string, trust: NitroTrust, run: Run) {
  const { stdout } = await run("python3", ["-B", custodyLedger, custodyTrust, "check-release-policy", candidate], 60_000);
  const roster = parseStrictJson<{ custodyKeys: string[]; nextCutover: string | null }>(stdout, ["custodyKeys", "nextCutover"]);
  const expected = trust.custodyKeys;
  if (!Array.isArray(roster.custodyKeys) || roster.custodyKeys.length !== expected.length ||
      !expected.every(key => roster.custodyKeys.includes(key))) {
    throw new Error("activation requires the active custody approval roster");
  }
  return roster.nextCutover === null ? undefined : decodeDecimalU64(roster.nextCutover) * 1_000n;
}

export function bucketPolicy(trust: NitroTrust, name: string, administrator: string, publisher: string) {
  const { bucket, account, key } = publicationFor(trust, name);
  const ownerRole = new RegExp(`^arn:aws:iam::${account}:role/[A-Za-z0-9+=,.@_/-]+$`);
  if (!ownerRole.test(publisher) || !ownerRole.test(administrator) || publisher === administrator) {
    throw new Error("use separate administrator and publisher roles in the publication account");
  }
  const bucketArn = `arn:aws:s3:::${bucket}`;
  const resource = `${bucketArn}/${key}`;
  return { Version: "2012-10-17", Statement: [
    { Sid: "RestrictBucketAdministration", Effect: "Deny", Principal: "*", Resource: bucketArn,
      Action: ["s3:DeleteBucket", "s3:DeleteBucketPolicy", "s3:PutBucketPolicy", "s3:PutBucketVersioning",
        "s3:PutLifecycleConfiguration", "s3:PutReplicationConfiguration", "s3:PutBucketOwnershipControls",
        "s3:PutBucketAcl", "s3:PutBucketPublicAccessBlock", "s3:PutEncryptionConfiguration",
        "s3:PutBucketObjectLockConfiguration", "s3:PutBucketCORS"],
      Condition: { StringNotEquals: { "aws:PrincipalArn": administrator } } },
    { Sid: "ReadPublishedPolicy", Effect: "Allow", Principal: "*", Action: "s3:GetObject", Resource: resource },
    { Sid: "PublishPolicy", Effect: "Allow", Principal: { AWS: publisher }, Action: "s3:PutObject", Resource: resource },
    { Sid: "RestrictPublisher", Effect: "Deny", Principal: "*", Action: "s3:PutObject", Resource: resource,
      Condition: { StringNotEquals: { "aws:PrincipalArn": publisher } } },
    { Sid: "RequireConditionalPublication", Effect: "Deny", Principal: "*", Action: "s3:PutObject", Resource: resource,
      Condition: { StringNotEquals: { "s3:if-none-match": "*" }, Null: { "s3:if-match": "true" } } },
    { Sid: "KeepPolicyHistory", Effect: "Deny", Principal: "*", Resource: resource,
      Action: ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:ReplicateObject", "s3:ReplicateDelete"] },
  ] };
}

export async function publish(
  trust: NitroTrust, name: string, text: string,
  { custodyTrust, nextTrust, emergencyFrom, run = runCommand, probe = probeNitroTarget }: PublicationOptions = {},
): Promise<void> {
  validateNitroTrust(trust);
  const { bucket, region, account, key } = publicationFor(trust, name);
  const [first, second] = trust.publications;
  const isSecond = bucket === second.bucket;
  async function readPeer() {
    const { url, account } = nitroPublication(trust, isSecond ? first : second);
    return readNitroPolicy(url, AbortSignal.timeout(5_000), account);
  }
  const primary = isSecond ? await readPeer() : undefined;
  const now = BigInt(Date.now());
  const verify = (pins: NitroTrust, at: bigint, witness: string | undefined) => witness === undefined
    ? verifyNitroPolicy(text, pins, at)
    : verifyNitroMirrorPolicy(text, witness, pins, at);
  const verified = verify(trust, now, primary);
  const { policy, signatures, custodySignatures } = verified;
  const activatesPrimary = !isSecond && policy.action === "activate";
  if (activatesPrimary && !custodyTrust) throw new Error("activation requires --custody-trust");
  if (nextTrust && emergencyFrom) throw new Error("choose one signer transition");
  if (nextTrust) {
    validateNitroTrust(nextTrust);
    requireNitroTrustTransition(trust, nextTrust, policy.sequence);
    verify(nextTrust, now, primary);
  }
  if (emergencyFrom) {
    validateNitroTrust(emergencyFrom);
    requireNitroTrustTransition(emergencyFrom, trust, policy.sequence);
  }
  const other = nextTrust ?? emergencyFrom;
  if (signatures.some(({ key }) => !trust.keys.includes(key) && !other?.keys.includes(key)) ||
      custodySignatures.some(({ key }) => !trust.custodyKeys.includes(key) && !other?.custodyKeys.includes(key))) {
    throw new Error("publication includes signers outside the supplied trust bundles");
  }
  const directory = await mkdtemp(join(tmpdir(), "spr-release-"));
  const candidate = join(directory, "candidate.json");
  const current = join(directory, "current.json");

  async function call(operation: string, args: readonly string[]) {
    return run("aws", ["--region", region, "--no-cli-pager", "--output", "json", "s3api", operation,
      "--bucket", bucket, "--expected-bucket-owner", account, "--key", key, ...args], 25_000);
  }

  async function readHead() {
    const { stdout } = await call("get-object", ["--range", `bytes=0-${MAX_BYTES}`, current]);
    const { ETag: etag } = JSON.parse(stdout) as { ETag: string };
    if (typeof etag !== "string" || !/^"[^"\s]{1,128}"$/.test(etag)) throw new Error("invalid S3 revision");
    return { etag, text: await readPolicy(current) };
  }

  try {
    await writeFile(candidate, text, { mode: 0o600, flag: "wx" });
    let head: Awaited<ReturnType<typeof readHead>> | undefined;
    if (policy.sequence !== "1") head = await readHead();
    else if (isSecond) {
      // If the mirror has no readable genesis, S3 must still enforce creation only.
      head = await readHead().catch(() => undefined);
    }
    if (head?.text === text) return;
    if (!nextNitroPublication(verified, head?.text, trust, emergencyFrom)) {
      if (!isSecond || !head) throw new Error("use a new revision to change published signatures");
      const previous = parseStrictJson<Pick<typeof verified, "signatures" | "custodySignatures">>(head.text);
      for (const scope of ["signatures", "custodySignatures"] as const) {
        const keys = new Set(verified[scope].map(({ key }) => key));
        if (previous[scope].some(({ key }) => !keys.has(key))) {
          throw new Error("mirror repair must preserve the existing signers for this revision");
        }
      }
    }
    async function checkMirror() {
      if (isSecond || !head) return;
      const peer = await readPeer();
      if (peer === head.text || peer === text) return;
      if (policy.action === "revoke" && nextNitroPublication(verified, peer, trust, emergencyFrom)) return;
      throw new Error("the mirror must hold the same signed predecessor before the primary advances");
    }
    await checkMirror();
    let confirmedCutover: bigint | undefined;
    let probes: ReplicaProbe[] = [];
    if (activatesPrimary && custodyTrust) {
      const custodyPins = nextTrust ?? trust;
      const cutover = await checkActivationRoster(candidate, custodyTrust, custodyPins, run);
      requireCustodyWriteWindow(cutover, BigInt(Date.now()));
      probes = await Promise.all(policy.targets.map(target => probe(target, trust)));
      await checkMirror();
      confirmedCutover = await checkActivationRoster(candidate, custodyTrust, custodyPins, run);
    }
    const latestPrimary = isSecond ? await readPeer() : undefined;
    const beforeWrite = BigInt(Date.now());
    verify(trust, beforeWrite, latestPrimary);
    if (!isSecond && verified.expiresAt <= beforeWrite + WRITE_MARGIN_MS) {
      throw new Error("the signed policy expires too soon for conditional publication");
    }
    requireCustodyWriteWindow(confirmedCutover, beforeWrite);
    requireFreshProbes(probes, beforeWrite, Number(WRITE_MARGIN_MS));
    const precondition = head ? ["--if-match", head.etag] : ["--if-none-match", "*"];
    try {
      await call("put-object", [...precondition, "--content-type", "application/json", "--cache-control", "no-store", "--body", candidate]);
    } catch (writeError) {
      const observed = await readHead().catch((readError: unknown) => {
        throw new Error(`policy write could not be confirmed. Write failed with ${writeError}. Readback failed with ${readError}`,
          { cause: new AggregateError([writeError, readError]) });
      });
      if (observed.text !== text) throw writeError;
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function pinnedPublication(trust: NitroTrust) {
  const published = await readPublishedNitroPolicy(trust, AbortSignal.timeout(5_000));
  const { sameEnvelope, checkpoint } = published;
  if (!sameEnvelope) throw new Error("both buckets must serve the same signed policy file");
  if (checkpoint.sequence !== trust.minimumSequence || checkpoint.digest !== trust.minimumPolicyDigest ||
      checkpoint.minimumCustodyEpoch !== trust.minimumCustodyEpoch ||
      checkpoint.recoveryOnly !== (trust.recoveryOnly ?? false)) {
    throw new Error("wallet pins must match the current policy agreed by both buckets");
  }
  return published;
}

/** Verify the exact current, witnessed revision before shipping a new pin file. */
export async function verifyDistributionPins(
  trust: NitroTrust,
  { custodyTrust, run = runCommand, probe = probeNitroTarget }: Pick<PublicationOptions, "custodyTrust" | "run" | "probe"> = {},
) {
  validateNitroTrust(trust);
  const published = await pinnedPublication(trust);
  if (published.policy.action === "revoke") return published.checkpoint;
  if (!custodyTrust) throw new Error("activation requires --custody-trust");

  const directory = await mkdtemp(join(tmpdir(), "spr-wallet-trust-"));
  try {
    const candidate = join(directory, "published.json");
    await writeFile(candidate, published.text, { mode: 0o600, flag: "wx" });
    await checkActivationRoster(candidate, custodyTrust, trust, run);
    const probes = await Promise.all(published.policy.targets.map(target => probe(target, trust)));
    const nextCutover = await checkActivationRoster(candidate, custodyTrust, trust, run);
    const confirmed = await pinnedPublication(trust);
    if (confirmed.text !== published.text) throw new Error("signed policy changed during wallet trust verification");
    const now = BigInt(Date.now());
    if (nextCutover !== undefined && now >= nextCutover) {
      throw new Error("custody approval roster changed during wallet trust verification");
    }
    requireFreshProbes(probes, now);
    return confirmed.checkpoint;
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function main() {
  const [trustPath, bucket, ...args] = process.argv.slice(2);
  const usage = "usage: nitro-publish.ts <wallet-trust.json> --check-wallet-trust [--custody-trust <custody-trust.json>] | nitro-publish.ts <wallet-trust.json> <bucket> <signed-policy.json> [--custody-trust <custody-trust.json>] [--next-trust <incoming.json> | --emergency-from <outgoing.json>] | <wallet-trust.json> <bucket> --bucket-policy <administrator-role> <publisher-role>";
  if (!trustPath || !bucket) {
    throw new Error(usage);
  }
  const trustText = await readPolicy(trustPath);
  const trust = parseStrictJson<NitroTrust>(trustText);
  if (bucket === "--check-wallet-trust") {
    const { values: { "custody-trust": custodyTrust } } = parseArgs({ args, options: { "custody-trust": { type: "string" } } });
    const checkpoint = await verifyDistributionPins(trust, { ...(custodyTrust ? { custodyTrust } : {}) });
    const trustSha256 = createHash("sha256").update(trustText).digest("hex");
    console.log(JSON.stringify({ ...checkpoint, trustSha256 }, null, 2));
    return;
  }
  const [policyPath, ...extra] = args;
  if (!policyPath) throw new Error(usage);
  validateNitroTrust(trust);
  if (policyPath === "--bucket-policy") {
    const [administrator, publisher] = extra;
    if (!administrator || !publisher || extra.length !== 2) throw new Error(usage);
    console.log(JSON.stringify(bucketPolicy(trust, bucket, administrator, publisher), null, 2));
    return;
  }
  const { values: { "custody-trust": custodyTrust, "next-trust": nextPath, "emergency-from": emergencyPath } } = parseArgs({
    args: extra, options: { "custody-trust": { type: "string" }, "next-trust": { type: "string" }, "emergency-from": { type: "string" } },
  });
  const nextTrust = nextPath && parseStrictJson<NitroTrust>(await readPolicy(nextPath));
  const emergencyFrom = emergencyPath && parseStrictJson<NitroTrust>(await readPolicy(emergencyPath));
  await publish(trust, bucket, await readPolicy(policyPath), {
    ...(custodyTrust ? { custodyTrust } : {}),
    ...(nextTrust ? { nextTrust } : {}),
    ...(emergencyFrom ? { emergencyFrom } : {}),
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
