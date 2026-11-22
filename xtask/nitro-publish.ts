import { execFile } from "node:child_process";
import { mkdtemp, open, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs, promisify } from "node:util";
import { connectNitroTarget } from "../sdk/src/attestation/nitro-connection.js";
import {
  nextNitroPublication, nitroPublication, validateNitroTrust, verifyNitroPolicy, type NitroTrust,
} from "../sdk/src/attestation/nitro-policy.js";
import { readNitroPolicy } from "../sdk/src/attestation/nitro-publication.js";
import { parseStrictJson } from "../sdk/src/protocol/json.js";

const execute = promisify(execFile);
const MAX_BYTES = 32_768;
const custodyLedger = fileURLToPath(new URL("../enclave/deploy/nitro/custody_ledger.py", import.meta.url));
type Run = (command: string, args: string[], timeout: number) => Promise<{ stdout: string }>;
const runCommand: Run = (command, args, timeout) => execute(command, args, { timeout, maxBuffer: 64 * 1024 });

type PublicationOptions = {
  custodyTrust?: string;
  previousTrust?: NitroTrust;
  run?: Run;
};

async function readPolicy(path: string): Promise<string> {
  const file = await open(path, "r");
  try {
    const buffer = Buffer.alloc(MAX_BYTES + 1);
    let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await file.read(buffer, size, buffer.length - size, size);
      if (bytesRead === 0) break;
      size += bytesRead;
    }
    if (size > MAX_BYTES) throw new Error("release policy exceeds 32 KiB");
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, size));
  } finally {
    await file.close();
  }
}

function publicationFor(trust: NitroTrust, bucket: string) {
  const publication = trust.publications.find(candidate => candidate.bucket === bucket);
  if (!publication) throw new Error("expected one of the pinned publication buckets");
  return nitroPublication(trust, publication);
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
  trust: NitroTrust, name: string, text: string, { custodyTrust, previousTrust = trust, run = runCommand }: PublicationOptions = {},
): Promise<void> {
  const now = BigInt(Date.now());
  const { policy } = verifyNitroPolicy(text, trust, now);
  if (policy.action === "activate" && !custodyTrust) throw new Error("activation requires --custody-trust");
  const { bucket, region, account, key } = publicationFor(trust, name);
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
    const head = policy.sequence === "1" ? undefined : await readHead();
    if (!nextNitroPublication(text, head?.text, trust, now, previousTrust)) return;
    const [first, second] = trust.publications;
    const isSecond = bucket === second.bucket;
    if (isSecond || head) {
      const { url, account } = nitroPublication(trust, isSecond ? first : second);
      const peer = await readNitroPolicy(url, AbortSignal.timeout(5_000), account);
      if (nextNitroPublication(text, peer, trust, now, previousTrust) && isSecond) {
        throw new Error("publish the exact policy to the first bucket before mirroring it");
      }
    }
    if (policy.action === "activate" && custodyTrust) {
      await run("python3", ["-B", custodyLedger, custodyTrust, "check-serving-policy", candidate], 60_000);
    }
    await Promise.all(policy.targets.map(target => connectNitroTarget(target, trust)));
    verifyNitroPolicy(text, trust, BigInt(Date.now()));
    const precondition = head ? ["--if-match", head.etag] : ["--if-none-match", "*"];
    try {
      await call("put-object", [...precondition, "--content-type", "application/json", "--cache-control", "no-store", "--body", candidate]);
    } catch (error) {
      // A retry is successful only if S3 already holds this exact signed policy.
      const observed = await readHead();
      if (nextNitroPublication(text, observed.text, trust, now, previousTrust)) throw error;
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function main() {
  const [trustPath, bucket, policyPath, ...extra] = process.argv.slice(2);
  const usage = "usage: nitro-publish.ts <wallet-trust.json> <bucket> <signed-policy.json> [--custody-trust <custody-trust.json>] [--previous-trust <old-trust.json>] | <wallet-trust.json> <bucket> --bucket-policy <administrator-role> <publisher-role>";
  if (!trustPath || !bucket || !policyPath) {
    throw new Error(usage);
  }
  const trust = parseStrictJson<NitroTrust>(await readFile(trustPath, "utf8"));
  validateNitroTrust(trust);
  if (policyPath === "--bucket-policy") {
    const [administrator, publisher] = extra;
    if (!administrator || !publisher || extra.length !== 2) throw new Error(usage);
    console.log(JSON.stringify(bucketPolicy(trust, bucket, administrator, publisher), null, 2));
    return;
  }
  const { values: { "custody-trust": custodyTrust, "previous-trust": previousPath } } = parseArgs({
    args: extra, options: { "custody-trust": { type: "string" }, "previous-trust": { type: "string" } },
  });
  const previousTrust = previousPath ? parseStrictJson<NitroTrust>(await readFile(previousPath, "utf8")) : trust;
  validateNitroTrust(previousTrust);
  await publish(trust, bucket, await readPolicy(policyPath), { previousTrust, ...(custodyTrust ? { custodyTrust } : {}) });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
