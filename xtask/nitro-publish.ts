import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs, promisify } from "node:util";
import {
  authenticateNitroPolicy, nextNitroPublication, nitroPublication, requireNitroTrustTransition, validateNitroTrust,
  verifyNitroMirrorPolicy, verifyNitroPolicy, verifyStoredNitroPolicy, type NitroPolicy, type NitroTarget, type NitroTrust,
} from "../sdk/src/attestation/nitro-policy.js";
import { readNitroPolicy, readPublishedNitroPolicy } from "../sdk/src/attestation/nitro-publication.js";
import { probeNitroTarget } from "../sdk/src/client/nitro-probe.js";
import { remainingReleasePolicyMs } from "../sdk/src/connection/operations.js";
import { decodeDecimalU64 } from "../sdk/src/protocol/decimal.js";
import { DecryptionServiceError } from "../sdk/src/protocol/error.js";
import { canonicalizeJsonValue } from "../sdk/src/protocol/jcs.js";
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
  replicaProfile?: string;
  publicationProfiles?: readonly string[];
  nextTrust?: NitroTrust;
  emergencyFrom?: NitroTrust;
  run?: Run;
  probe?: (target: NitroTarget, trust: NitroTrust) => Promise<ReplicaProbe>;
};

type ReplicaProbe = {
  readonly bootstrapSlots: readonly [number, number, number];
  readonly window: Awaited<ReturnType<typeof probeNitroTarget>>["window"];
};

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

function publicationStorage({ bucket, region, account }: ReturnType<typeof publicationFor>, run: Run, profile?: string) {
  const credentials = profile === undefined ? [] : ["--profile", profile];
  return (operation: string, args: readonly string[], timeout = 25_000) =>
    run("aws", [...credentials, "--region", region, "--no-cli-pager", "--output", "json", "s3api", operation,
      "--bucket", bucket, "--expected-bucket-owner", account, ...args], timeout);
}

function etag(value: unknown): string {
  if (typeof value !== "string" || !/^"[^"\s]{1,128}"$/.test(value)) throw new Error("invalid S3 revision");
  return value;
}

function requireCustodyWriteWindow(nextCutover: bigint | undefined, now: bigint): void {
  if (nextCutover !== undefined && now + WRITE_MARGIN_MS >= nextCutover) {
    throw new Error("custody approval cutover is too close for publication");
  }
}

async function checkActivationRoster(
  candidate: string, custodyTrust: string, trust: NitroTrust, run: Run, replicaProfile?: string,
  paymentProbes?: readonly ReplicaProbe[],
) {
  const args = ["-B", custodyLedger, custodyTrust, "check-release-policy", candidate];
  if (replicaProfile !== undefined) args.push("--replica-profile", replicaProfile);
  if (paymentProbes && (trust.network === "mainnet" || replicaProfile !== undefined)) {
    args.push("--bootstrap-slots", JSON.stringify(paymentProbes.map(probe => probe.bootstrapSlots)));
  }
  const { stdout } = await run("python3", args, 60_000);
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

function paymentPublicationProfiles(trust: NitroTrust, policy: NitroPolicy, profiles?: readonly string[]) {
  if (policy.action !== "activate" || policy.recoveryOnly || (trust.network !== "mainnet" && profiles === undefined)) return;
  if (profiles?.length !== 2 || !profiles[0] || !profiles[1] || profiles[0] === profiles[1]) {
    throw new Error("provide --publication-profile twice in primary and mirror order");
  }
  return [profiles[0], profiles[1]] as const;
}

async function checkPublicationBuckets(
  trust: NitroTrust, profiles: readonly [string, string] | undefined, run: Run, requireHeadVersions = false,
) {
  if (profiles === undefined) return;
  await Promise.all(trust.publications.map(async (pin, index) => {
    const publication = nitroPublication(trust, pin);
    const storage = publicationStorage(publication, run, profiles[index]);
    async function read<T>(operation: string) {
      return parseStrictJson<T>((await storage(operation, [])).stdout);
    }
    const [versioning, ownership, response] = await Promise.all([
      read<{ Status?: string }>("get-bucket-versioning"),
      read<{ OwnershipControls?: unknown }>("get-bucket-ownership-controls"),
      read<{ Policy: string }>("get-bucket-policy"),
      storage("get-bucket-lifecycle-configuration", ["--cli-error-format", "json"]).then(() => {
        throw new Error(`publication bucket ${pin.bucket} must have no lifecycle configuration`);
      }, error => {
        if (error instanceof Error && "stderr" in error && typeof error.stderr === "string") {
          let reply: { Code?: string } | undefined;
          try {
            reply = parseStrictJson<{ Code?: string }>(error.stderr);
          } catch {
            throw error;
          }
          if (reply?.Code === "NoSuchLifecycleConfiguration") return;
        }
        throw error;
      }),
    ]);
    if (versioning.Status !== "Enabled") throw new Error(`publication bucket ${pin.bucket} requires versioning`);
    const ownerEnforced = { Rules: [{ ObjectOwnership: "BucketOwnerEnforced" }] };
    if (canonicalizeJsonValue(ownership.OwnershipControls ?? null) !== canonicalizeJsonValue(ownerEnforced)) {
      throw new Error(`publication bucket ${pin.bucket} requires bucket-owner-enforced ownership`);
    }
    const installed = parseStrictJson<{ Statement?: {
      Sid: string; Condition?: { StringNotEquals?: Record<string, unknown> }; Principal?: { AWS?: unknown };
    }[] }>(response.Policy);
    const statements = Array.isArray(installed?.Statement) ? installed.Statement : [];
    const administrator = statements.find(statement => statement?.Sid === "RestrictBucketAdministration")
      ?.Condition?.StringNotEquals?.["aws:PrincipalArn"];
    const publisher = statements.find(statement => statement?.Sid === "PublishPolicy")?.Principal?.AWS;
    if (typeof administrator !== "string" || typeof publisher !== "string" ||
        canonicalizeJsonValue(installed) !== canonicalizeJsonValue(bucketPolicy(trust, pin.bucket, administrator, publisher))) {
      throw new Error(`publication bucket ${pin.bucket} differs from the generated bucket policy`);
    }
    if (requireHeadVersions) {
      const { stdout } = await storage("head-object", ["--key", publication.key]);
      versionId(parseStrictJson<{ VersionId?: string }>(stdout).VersionId);
    }
  }));
}

export async function publish(
  trust: NitroTrust, name: string, text: string,
  { custodyTrust, replicaProfile, publicationProfiles, nextTrust, emergencyFrom, run = runCommand, probe = probeNitroTarget }: PublicationOptions = {},
): Promise<void> {
  validateNitroTrust(trust);
  const publication = publicationFor(trust, name);
  const { bucket, key } = publication;
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
  const profiles = isSecond ? undefined : paymentPublicationProfiles(trust, policy, publicationProfiles);
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

  const storage = publicationStorage(publication, run);
  const call = (operation: string, args: readonly string[]) => storage(operation, ["--key", key, ...args]);

  async function readHead() {
    const { stdout } = await call("get-object", ["--range", `bytes=0-${MAX_BYTES}`, current]);
    const { ETag } = JSON.parse(stdout) as { ETag: string };
    return { etag: etag(ETag), text: await readPolicy(current) };
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
      const cutover = await checkActivationRoster(candidate, custodyTrust, custodyPins, run, replicaProfile);
      requireCustodyWriteWindow(cutover, BigInt(Date.now()));
      probes = await Promise.all(policy.targets.map(target => probe(target, trust)));
      await checkMirror();
      [confirmedCutover] = await Promise.all([
        checkActivationRoster(candidate, custodyTrust, custodyPins, run, replicaProfile, policy.recoveryOnly ? undefined : probes),
        checkPublicationBuckets(trust, profiles, run),
      ]);
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

type StoredVersion = { VersionId: string; Size: number };

function versionId(value: unknown): string {
  if (typeof value !== "string" || value === "null" || !/^[!-~]{1,1024}$/.test(value)) {
    throw new Error("expected an original S3 policy version");
  }
  return value;
}

/** Restore the exact retained policy in one bucket using the other bucket as witness. */
export async function restorePublication(trust: NitroTrust, name: string, retainedVersion: string, { run = runCommand }: Pick<PublicationOptions, "run"> = {}) {
  validateNitroTrust(trust);
  versionId(retainedVersion);
  const publication = publicationFor(trust, name);
  const { key } = publication;
  const [primary, mirror] = trust.publications;
  const isPrimary = name === primary.bucket;
  const peer = nitroPublication(trust, isPrimary ? mirror : primary);
  const deadline = performance.now() + 180_000;
  const storage = publicationStorage(publication, run);
  async function call(operation: string, args: readonly string[]) {
    const remaining = Math.floor(deadline - performance.now());
    if (remaining <= 0) throw new Error("policy restoration exceeded its deadline");
    return storage(operation, args, Math.min(25_000, remaining));
  }
  async function head() {
    const { stdout } = await call("head-object", ["--key", key]);
    const result = JSON.parse(stdout) as { VersionId: unknown; ETag: unknown; ContentLength: number };
    return { VersionId: versionId(result.VersionId), Size: result.ContentLength, etag: etag(result.ETag) };
  }
  const directory = await mkdtemp(join(tmpdir(), "spr-policy-restore-"));
  const path = join(directory, "policy.json");
  async function readVersion(version: StoredVersion) {
    if (!Number.isSafeInteger(version.Size) || version.Size < 0) throw new Error("invalid S3 policy size");
    if (version.Size === 0 || version.Size > MAX_BYTES) return undefined;
    const { stdout } = await call("get-object", [
      "--key", key, "--version-id", versionId(version.VersionId), "--range", `bytes=0-${MAX_BYTES}`, path,
    ]);
    if (JSON.parse(stdout).VersionId !== version.VersionId) throw new Error("S3 returned a different policy version");
    try {
      const text = await readPolicy(path);
      if (Buffer.byteLength(text) !== version.Size) throw new Error("S3 policy size differs from the retained version");
      return text;
    } catch (error) {
      if (error instanceof TypeError) return undefined; // Malformed UTF-8.
      throw error;
    }
  }

  try {
    const damaged = await head();
    let tokens: string[] = [];
    const seen = new Set<string>();
    const later: StoredVersion[] = [];
    let retained: StoredVersion | undefined;
    while (!retained) {
      const { stdout } = await call("list-object-versions", ["--prefix", key, "--max-keys", "64", "--no-paginate", ...tokens]);
      const page = JSON.parse(stdout) as {
        Versions?: (StoredVersion & { Key: string; IsLatest: boolean })[];
        DeleteMarkers?: { Key: string }[];
        IsTruncated: boolean;
        NextKeyMarker?: string;
        NextVersionIdMarker?: string;
      };
      if (page.DeleteMarkers?.some(marker => marker.Key === key) || typeof page.IsTruncated !== "boolean") {
        throw new Error("cannot verify the current policy version history");
      }
      for (const row of page.Versions ?? []) {
        if (row.Key !== key) continue;
        const id = versionId(row.VersionId);
        if (seen.has(id) || (seen.size === 0 ? id !== damaged.VersionId || row.IsLatest !== true : row.IsLatest !== false)) {
          throw new Error("policy head changed during restoration");
        }
        seen.add(id);
        if (id === retainedVersion) {
          retained = row;
          break;
        }
        later.push(row);
      }
      if (retained) break;
      if (!page.IsTruncated || page.NextKeyMarker !== key || page.NextVersionIdMarker === tokens.at(-1)) {
        throw new Error("retained policy version is missing");
      }
      tokens = ["--key-marker", key, "--version-id-marker", versionId(page.NextVersionIdMarker)];
    }
    const text = await readVersion(retained);
    if (text === undefined) throw new Error("retained policy version has an invalid body");
    authenticateNitroPolicy(text, trust);
    let alreadyRestored = later.length === 0;
    for (const version of later) {
      const observed = await readVersion(version);
      if (observed === text && version.VersionId === damaged.VersionId) alreadyRestored = true;
      if (observed === undefined || observed === text) continue;
      try {
        authenticateNitroPolicy(observed, trust);
      } catch (error) {
        if (error instanceof DecryptionServiceError) continue;
        throw error;
      }
      throw new Error("a later S3 version contains a different authenticated policy");
    }
    const witness = await readNitroPolicy(peer.url, AbortSignal.timeout(5_000), peer.account);
    const primaryText = isPrimary ? text : witness;
    const primaryPolicy = verifyStoredNitroPolicy(primaryText, trust, BigInt(Date.now()));
    nextNitroPublication(primaryPolicy, isPrimary ? witness : text, trust);
    if (!alreadyRestored) await writeFile(path, text, { mode: 0o600 });
    const confirmed = await head();
    if (confirmed.VersionId !== damaged.VersionId || confirmed.etag !== damaged.etag) {
      throw new Error("policy head changed during restoration");
    }
    if (alreadyRestored) return;
    try {
      await call("put-object", ["--key", key, "--if-match", damaged.etag, "--content-type", "application/json",
        "--cache-control", "no-store", "--body", path]);
    } catch (error) {
      if (await head().then(readVersion).catch(() => undefined) !== text) throw error;
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

/** Verify the exact current, witnessed revision before shipping a new pin file. */
export async function verifyDistributionPins(
  trust: NitroTrust,
  { custodyTrust, replicaProfile, publicationProfiles, run = runCommand, probe = probeNitroTarget }:
  Pick<PublicationOptions, "custodyTrust" | "replicaProfile" | "publicationProfiles" | "run" | "probe"> = {},
) {
  validateNitroTrust(trust);
  const published = await pinnedPublication(trust);
  if (published.policy.action === "revoke") return published.checkpoint;
  if (!custodyTrust) throw new Error("activation requires --custody-trust");
  const profiles = paymentPublicationProfiles(trust, published.policy, publicationProfiles);

  const directory = await mkdtemp(join(tmpdir(), "spr-wallet-trust-"));
  try {
    const candidate = join(directory, "published.json");
    await writeFile(candidate, published.text, { mode: 0o600, flag: "wx" });
    await checkActivationRoster(candidate, custodyTrust, trust, run, replicaProfile);
    const probes = await Promise.all(published.policy.targets.map(target => probe(target, trust)));
    const [nextCutover] = await Promise.all([
      checkActivationRoster(candidate, custodyTrust, trust, run, replicaProfile, published.policy.recoveryOnly ? undefined : probes),
      checkPublicationBuckets(trust, profiles, run, true),
    ]);
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
  const activationOptions = "[--custody-trust <custody-trust.json>] [--replica-profile <aws-profile>] [--publication-profile <primary> --publication-profile <mirror>]";
  const usage = `usage: nitro-publish.ts <wallet-trust.json> --check-wallet-trust ${activationOptions} | nitro-publish.ts <wallet-trust.json> <bucket> <signed-policy.json> ${activationOptions} [--next-trust <incoming.json> | --emergency-from <outgoing.json>] | <wallet-trust.json> <bucket> --bucket-policy <administrator-role> <publisher-role> | <wallet-trust.json> <bucket> --restore-from <version-id>`;
  const activationFlags = {
    "custody-trust": { type: "string" }, "replica-profile": { type: "string" },
    "publication-profile": { type: "string", multiple: true },
  } as const;
  if (!trustPath || !bucket) {
    throw new Error(usage);
  }
  const trustText = await readPolicy(trustPath);
  const trust = parseStrictJson<NitroTrust>(trustText);
  if (bucket === "--check-wallet-trust") {
    const { values: { "custody-trust": custodyTrust, "replica-profile": replicaProfile, "publication-profile": publicationProfiles } } =
      parseArgs({ args, options: activationFlags });
    const checkpoint = await verifyDistributionPins(trust, {
      ...(custodyTrust ? { custodyTrust } : {}), ...(replicaProfile ? { replicaProfile } : {}),
      ...(publicationProfiles ? { publicationProfiles } : {}),
    });
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
  if (policyPath === "--restore-from") {
    if (extra.length !== 1) throw new Error(usage);
    await restorePublication(trust, bucket, extra[0]!);
    return;
  }
  const { values: {
    "custody-trust": custodyTrust, "replica-profile": replicaProfile, "publication-profile": publicationProfiles,
    "next-trust": nextPath, "emergency-from": emergencyPath,
  } } = parseArgs({
    args: extra, options: { ...activationFlags, "next-trust": { type: "string" }, "emergency-from": { type: "string" } },
  });
  const nextTrust = nextPath && parseStrictJson<NitroTrust>(await readPolicy(nextPath));
  const emergencyFrom = emergencyPath && parseStrictJson<NitroTrust>(await readPolicy(emergencyPath));
  await publish(trust, bucket, await readPolicy(policyPath), {
    ...(custodyTrust ? { custodyTrust } : {}),
    ...(replicaProfile ? { replicaProfile } : {}),
    ...(publicationProfiles ? { publicationProfiles } : {}),
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
