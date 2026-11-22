import { sha256 } from "@noble/hashes/sha256";
import { parseUncompressedSec1, verifyP256Prehash } from "../crypto/p256.js";
import { decodeDecimalU64 } from "../protocol/decimal.js";
import { DecryptionServiceError } from "../protocol/error.js";
import { encodeLowerHex, requireHex } from "../protocol/hex.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import { assertExactObjectKeys, parseStrictJson } from "../protocol/json.js";
import type { Network } from "../protocol/types.js";

export type NitroPcrs = Readonly<Record<0 | 1 | 2 | 3, string>>;

export type NitroTarget = {
  readonly endpoint: string;
  readonly releaseId: string;
  readonly executableSha256: string;
  readonly custodyEpoch: string;
  readonly custodyDigest: string;
  readonly pcrs: NitroPcrs;
};

export type NitroPolicy = {
  readonly version: 1;
  readonly action: "activate" | "revoke";
  readonly network: Network;
  readonly securityDomainId: string;
  readonly noteSeedCommitment: string;
  readonly minimumCustodyEpoch: string;
  readonly sequence: string;
  readonly previousPolicyDigest: string | null;
  readonly validFromMs: string;
  readonly expiresAtMs: string;
  readonly targets: readonly NitroTarget[];
};

type Publication = Readonly<{ bucket: string; region: string; account: string }>;

export type NitroTrust = {
  readonly network: Network;
  readonly securityDomainId: string;
  readonly noteSeedCommitment: string;
  readonly minimumCustodyEpoch: string;
  readonly minimumSequence: string;
  readonly publications: readonly [Publication, Publication];
  readonly threshold: number;
  /** Uncompressed SEC1 P-256 public keys pinned by the wallet integrator. */
  readonly keys: readonly string[];
};

export type NitroPolicyCheckpoint = {
  readonly sequence: string;
  readonly digest: string;
  readonly minimumCustodyEpoch: string;
};

/**
 * An atomic durable compare-and-set per pinned network and security domain.
 * Accept a higher sequence or the identical checkpoint. The custody floor
 * may only increase. Refuse writes which cannot persist.
 */
export type NitroPolicyStore = {
  current(): Promise<NitroPolicyCheckpoint | undefined>;
  accept(checkpoint: NitroPolicyCheckpoint): Promise<boolean>;
};

const MAX_TARGETS = 8;
const MAX_AUTHORITIES = 8;
const MAX_LIFETIME_MS = 7n * 24n * 60n * 60n * 1000n;
const POLICY_KEYS = [
  "version", "action", "network", "securityDomainId", "noteSeedCommitment", "sequence",
  "validFromMs", "expiresAtMs", "minimumCustodyEpoch", "previousPolicyDigest", "targets",
];
const TARGET_KEYS = ["endpoint", "releaseId", "executableSha256", "custodyEpoch", "custodyDigest", "pcrs"];
const te = new TextEncoder();

function invalid(): never {
  throw new DecryptionServiceError("ReleasePolicyInvalid");
}

function checkDigest(value: unknown, length: number): void {
  if (typeof value !== "string" || !requireHex(value, length).some(byte => byte !== 0)) invalid();
}

export function nitroEndpoint(text: string, network: Network): URL {
  if (typeof text !== "string" || text.length > 512) invalid();
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return invalid();
  }
  const devnetLoopback = network === "devnet" && url.protocol === "http:" &&
    (url.hostname === "127.0.0.1" || url.hostname === "[::1]");
  if (url.href !== text || url.username || url.password || url.search || url.hash ||
      (url.protocol !== "https:" && !devnetLoopback)) invalid();
  return url;
}

export function nitroPublication(trust: NitroTrust, publication: Publication) {
  assertExactObjectKeys(publication, ["bucket", "region", "account"], "ReleasePolicyInvalid");
  const { bucket, region, account } = publication;
  if (typeof bucket !== "string" || !/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(bucket) ||
      typeof region !== "string" || !/^[a-z]{2}-[a-z]+-[1-9][0-9]*$/.test(region) ||
      typeof account !== "string" || !/^[0-9]{12}$/.test(account)) invalid();
  const key = `spr-release/${trust.network}/${trust.securityDomainId}/policy.json`;
  return { bucket, region, account, key, url: new URL(`https://${bucket}.s3.${region}.amazonaws.com/${key}`) };
}

export function nitroPolicySigningDigest(policy: NitroPolicy): Uint8Array {
  return sha256(te.encode("SPR/native-nitro/release-policy/v1" + canonicalizeJsonValue(policy)));
}

export function validateNitroTrust(trust: NitroTrust): void {
  if (trust.network !== "devnet" && trust.network !== "mainnet") invalid();
  checkDigest(trust.securityDomainId, 32);
  checkDigest(trust.noteSeedCommitment, 32);
  if (!Array.isArray(trust.publications) || trust.publications.length !== 2) invalid();
  const first = nitroPublication(trust, trust.publications[0]);
  const second = nitroPublication(trust, trust.publications[1]);
  if (first.bucket === second.bucket || first.account === second.account) invalid();
  if (decodeDecimalU64(trust.minimumSequence) < 1n || decodeDecimalU64(trust.minimumCustodyEpoch) < 1n ||
      !Array.isArray(trust.keys) || trust.keys.length > MAX_AUTHORITIES ||
      !Number.isSafeInteger(trust.threshold) || trust.threshold < 2 ||
      trust.threshold > trust.keys.length || new Set(trust.keys).size !== trust.keys.length) invalid();
  for (const key of trust.keys) parseUncompressedSec1(requireHex(key, 65));
}

function verifySignedPolicy(text: string, trust: NitroTrust) {
  const { policy, signatures } = parseStrictJson<{
    policy: NitroPolicy;
    signatures: readonly { key: string; signature: string }[];
  }>(text, ["policy", "signatures"]);
  assertExactObjectKeys(policy, POLICY_KEYS, "ReleasePolicyInvalid");
  if (policy.version !== 1 || policy.network !== trust.network ||
      policy.securityDomainId !== trust.securityDomainId ||
      policy.noteSeedCommitment !== trust.noteSeedCommitment) invalid();
  const sequence = decodeDecimalU64(policy.sequence);
  const floor = decodeDecimalU64(policy.minimumCustodyEpoch);
  const validFrom = decodeDecimalU64(policy.validFromMs);
  const expiresAt = decodeDecimalU64(policy.expiresAtMs);
  if (sequence === 0n || floor === 0n || expiresAt <= validFrom || expiresAt - validFrom > MAX_LIFETIME_MS) invalid();
  if (sequence === 1n) {
    if (policy.previousPolicyDigest !== null) invalid();
  } else {
    checkDigest(policy.previousPolicyDigest, 32);
  }
  if (!Array.isArray(policy.targets) || policy.targets.length > MAX_TARGETS) invalid();
  if (policy.action === "activate" ? policy.targets.length === 0 : policy.action !== "revoke" || policy.targets.length !== 0) invalid();
  const endpoints = new Set<string>();
  const records = new Map<string, string>();
  for (const target of policy.targets) {
    assertExactObjectKeys(target, TARGET_KEYS, "ReleasePolicyInvalid");
    const endpoint = nitroEndpoint(target.endpoint, policy.network).href;
    if (endpoints.has(endpoint) || typeof target.releaseId !== "string" ||
        !/^[a-z0-9][a-z0-9-]{0,63}$/.test(target.releaseId)) invalid();
    endpoints.add(endpoint);
    checkDigest(target.executableSha256, 32);
    checkDigest(target.custodyDigest, 32);
    if (decodeDecimalU64(target.custodyEpoch) < floor) invalid();
    const known = records.get(target.custodyEpoch);
    if (known !== undefined && known !== target.custodyDigest) invalid();
    records.set(target.custodyEpoch, target.custodyDigest);
    assertExactObjectKeys(target.pcrs, ["0", "1", "2", "3"], "ReleasePolicyInvalid");
    for (const pcr of Object.values(target.pcrs)) checkDigest(pcr, 48);
  }
  if (!Array.isArray(signatures) || signatures.length < trust.threshold ||
      signatures.length > trust.keys.length) invalid();
  const digest = nitroPolicySigningDigest(policy);
  const accepted = new Set<string>();
  for (const signature of signatures) {
    assertExactObjectKeys(signature, ["key", "signature"], "ReleasePolicyInvalid");
    const { key } = signature;
    if (!trust.keys.includes(key) || accepted.has(key)) invalid();
    verifyP256Prehash(requireHex(key, 65), digest, requireHex(signature.signature, 64));
    accepted.add(key);
  }
  return {
    policy, validFrom, expiresAt,
    checkpoint: { sequence: policy.sequence, digest: encodeLowerHex(digest), minimumCustodyEpoch: policy.minimumCustodyEpoch },
  };
}

type VerifiedPolicy = ReturnType<typeof verifySignedPolicy>;

function requireCurrent({ policy, validFrom, expiresAt }: VerifiedPolicy, trust: NitroTrust, now: bigint): void {
  if (decodeDecimalU64(policy.sequence) < decodeDecimalU64(trust.minimumSequence) ||
      decodeDecimalU64(policy.minimumCustodyEpoch) < decodeDecimalU64(trust.minimumCustodyEpoch) ||
      now < validFrom || now >= expiresAt) invalid();
}

export function verifyNitroPolicy(text: string, trust: NitroTrust, now: bigint): VerifiedPolicy {
  const verified = verifySignedPolicy(text, trust);
  requireCurrent(verified, trust, now);
  return verified;
}

function requireSuccessor(prior: VerifiedPolicy, next: VerifiedPolicy): void {
  if (decodeDecimalU64(next.policy.sequence) !== decodeDecimalU64(prior.policy.sequence) + 1n ||
      next.policy.previousPolicyDigest !== prior.checkpoint.digest ||
      !advancesNitroPolicy(prior.checkpoint, next.checkpoint)) invalid();
  const priorRecords = new Map(prior.policy.targets.map(target => [target.custodyEpoch, target.custodyDigest]));
  if (next.policy.targets.some(target => priorRecords.has(target.custodyEpoch) &&
      priorRecords.get(target.custodyEpoch) !== target.custodyDigest)) invalid();
}

/** Both owners must return signed heads. Only the newest can authorize operations. */
export function verifyPublishedNitroPolicy(texts: readonly [string, string], trust: NitroTrust, now: bigint) {
  const first = verifySignedPolicy(texts[0], trust);
  const second = verifySignedPolicy(texts[1], trust);
  const agreed = first.checkpoint.digest === second.checkpoint.digest;
  const firstIsOlder = decodeDecimalU64(first.policy.sequence) < decodeDecimalU64(second.policy.sequence);
  const [prior, next] = firstIsOlder ? [first, second] : [second, first];
  if (!agreed) requireSuccessor(prior, next);
  requireCurrent(next, trust, now);
  return { ...next, agreed };
}

/** Validate a publication before writing it against the exact observed S3 ETag. */
export function nextNitroPublication(
  text: string, previous: string | undefined, trust: NitroTrust, now: bigint, previousTrust = trust,
): boolean {
  const next = verifyNitroPolicy(text, trust, now);
  if (!previous) {
    if (next.policy.sequence !== "1") invalid();
    return true;
  }
  const { policy } = parseStrictJson<{ policy: NitroPolicy }>(previous, ["policy", "signatures"]);
  if (previousTrust.network !== trust.network || previousTrust.securityDomainId !== trust.securityDomainId ||
      previousTrust.noteSeedCommitment !== trust.noteSeedCommitment ||
      canonicalizeJsonValue(previousTrust.publications) !== canonicalizeJsonValue(trust.publications)) invalid();
  const priorTrust = encodeLowerHex(nitroPolicySigningDigest(policy)) === next.checkpoint.digest ? trust : previousTrust;
  const prior = verifySignedPolicy(previous, priorTrust);
  if (prior.checkpoint.digest === next.checkpoint.digest) return false;
  requireSuccessor(prior, next);
  return true;
}

export function requireRetirementPolicy(
  { policy, agreed }: ReturnType<typeof verifyPublishedNitroPolicy>, replacementEpoch: string, custodyDigest: string,
) {
  if (!agreed || policy.action !== "activate" || decodeDecimalU64(policy.minimumCustodyEpoch) < decodeDecimalU64(replacementEpoch) ||
      !policy.targets.some(target => target.custodyEpoch === replacementEpoch && target.custodyDigest === custodyDigest)) invalid();
}

/** Returns true for a new policy or a repeat of the exact same policy. */
export function advancesNitroPolicy(current: NitroPolicyCheckpoint | undefined, next: NitroPolicyCheckpoint): boolean {
  if (!current) return true;
  const nextSequence = decodeDecimalU64(next.sequence);
  const currentSequence = decodeDecimalU64(current.sequence);
  return decodeDecimalU64(next.minimumCustodyEpoch) >= decodeDecimalU64(current.minimumCustodyEpoch) &&
    (nextSequence > currentSequence || (nextSequence === currentSequence &&
      next.digest === current.digest && next.minimumCustodyEpoch === current.minimumCustodyEpoch));
}
