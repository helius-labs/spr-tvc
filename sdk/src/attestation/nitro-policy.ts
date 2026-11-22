import { sha256 } from "@noble/hashes/sha256";
import { parseUncompressedSec1, verifyP256Prehash } from "../crypto/p256.js";
import { decodeDecimalU64 } from "../protocol/decimal.js";
import { DecryptionServiceError } from "../protocol/error.js";
import { encodeLowerHex, requireHex } from "../protocol/hex.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import { assertExactObjectKeys, parseStrictJson } from "../protocol/json.js";
import type { Network } from "../protocol/types.js";

export type NitroPcrs = Readonly<Record<0 | 1 | 2 | 3, string>>;
export type NitroTargetPcrs = NitroPcrs & Readonly<Record<4, string>>;

export type NitroTarget = {
  readonly endpoint: string;
  readonly releaseId: string;
  readonly executableSha256: string;
  readonly custodyEpoch: string;
  readonly custodyDigest: string;
  readonly pcrs: NitroTargetPcrs;
};

type Publication = Readonly<{ bucket: string; region: string; account: string }>;
type Publications = readonly [primary: Publication, mirror: Publication];

export type NitroPolicy = {
  readonly version: 1;
  readonly action: "activate" | "revoke";
  readonly recoveryOnly: boolean;
  readonly network: Network;
  readonly securityDomainId: string;
  readonly noteSeedCommitment: string;
  readonly publications: Publications;
  readonly minimumCustodyEpoch: string;
  readonly sequence: string;
  readonly previousPolicyDigest: string | null;
  readonly validFromMs: string;
  readonly expiresAtMs: string;
  readonly targets: readonly NitroTarget[];
};

export type NitroTrust = {
  readonly network: Network;
  readonly securityDomainId: string;
  readonly noteSeedCommitment: string;
  readonly minimumCustodyEpoch: string;
  readonly minimumSequence: string;
  /** Release-policy signing digest at minimumSequence. */
  readonly minimumPolicyDigest: string;
  /** Pin recovery mode when distributing the old domain after a cutover. */
  readonly recoveryOnly?: boolean;
  readonly publications: Publications;
  readonly threshold: number;
  /** Uncompressed SEC1 P-256 public keys pinned by the wallet integrator. */
  readonly keys: readonly string[];
  /** Three independently pinned custody approval keys in the same SEC1 format. */
  readonly custodyKeys: readonly string[];
};

export type NitroPolicyCheckpoint = {
  readonly sequence: string;
  readonly digest: string;
  readonly minimumCustodyEpoch: string;
  readonly recoveryOnly: boolean;
};

export type NitroPolicyRevision = Readonly<{
  checkpoint: NitroPolicyCheckpoint;
  previousPolicyDigest: string | null;
}>;

export type NitroPolicyUpdate = readonly [primary: NitroPolicyRevision, mirror: NitroPolicyRevision];

/**
 * Atomic durable compare-and-set scoped to the pinned network and security domain.
 * Return undefined from current only when no checkpoint is stored.
 * Run advancesNitroPolicy inside the write transaction and persist the primary checkpoint.
 */
export type NitroPolicyStore = {
  current(): Promise<NitroPolicyCheckpoint | undefined>;
  accept(update: NitroPolicyUpdate): Promise<boolean>;
};

const MAX_TARGETS = 8;
const MAX_AUTHORITIES = 8;
const CUSTODY_QUORUM = 2;
const CUSTODY_KEY_COUNT = 3;
const TRUST_KEYS = [
  "network", "securityDomainId", "noteSeedCommitment", "minimumCustodyEpoch",
  "minimumSequence", "minimumPolicyDigest", "publications", "threshold", "keys", "custodyKeys",
];
const POLICY_ENVELOPE_KEYS = ["policy", "signatures", "custodySignatures"];
const MAX_LIFETIME_MS = 7n * 24n * 60n * 60n * 1000n;
const POLICY_KEYS = [
  "version", "action", "network", "securityDomainId", "noteSeedCommitment", "sequence",
  "validFromMs", "expiresAtMs", "minimumCustodyEpoch", "previousPolicyDigest", "targets", "recoveryOnly", "publications",
];
const TARGET_KEYS = ["endpoint", "releaseId", "executableSha256", "custodyEpoch", "custodyDigest", "pcrs"];
const te = new TextEncoder();

function invalid(): never {
  throw new DecryptionServiceError("ReleasePolicyInvalid");
}

function checkDigest(value: unknown, length: number): void {
  if (typeof value !== "string" || !requireHex(value, length).some(byte => byte !== 0)) invalid();
}

export function isValidNitroPolicyCheckpoint(value: unknown): value is NitroPolicyCheckpoint {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const checkpoint = value as NitroPolicyCheckpoint;
  try {
    checkDigest(checkpoint.digest, 32);
    return typeof checkpoint.recoveryOnly === "boolean" && decodeDecimalU64(checkpoint.sequence) > 0n &&
      decodeDecimalU64(checkpoint.minimumCustodyEpoch) > 0n;
  } catch {
    return false;
  }
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

export function nitroCustodySigningDigest(policy: NitroPolicy): Uint8Array {
  return sha256(te.encode("SPR/native-nitro/custody-release-policy/v1" + canonicalizeJsonValue(policy)));
}

export function validateNitroTrust(trust: NitroTrust): void {
  if (typeof trust !== "object" || trust === null) invalid();
  const recoveryPin = Object.hasOwn(trust, "recoveryOnly");
  assertExactObjectKeys(trust, recoveryPin ? [...TRUST_KEYS, "recoveryOnly"] : TRUST_KEYS, "ReleasePolicyInvalid");
  if (trust.network !== "devnet" && trust.network !== "mainnet") invalid();
  if (recoveryPin && typeof trust.recoveryOnly !== "boolean") invalid();
  checkDigest(trust.securityDomainId, 32);
  checkDigest(trust.noteSeedCommitment, 32);
  checkDigest(trust.minimumPolicyDigest, 32);
  if (!Array.isArray(trust.publications) || trust.publications.length !== 2) invalid();
  const first = nitroPublication(trust, trust.publications[0]);
  const second = nitroPublication(trust, trust.publications[1]);
  if (first.bucket === second.bucket || first.account === second.account) invalid();
  if (decodeDecimalU64(trust.minimumSequence) < 1n || decodeDecimalU64(trust.minimumCustodyEpoch) < 1n ||
      !Array.isArray(trust.keys) || trust.keys.length > MAX_AUTHORITIES ||
      !Number.isSafeInteger(trust.threshold) || trust.threshold < 2 ||
      trust.threshold > trust.keys.length) invalid();
  if (!Array.isArray(trust.custodyKeys) || trust.custodyKeys.length !== CUSTODY_KEY_COUNT) invalid();
  const keys = [...trust.keys, ...trust.custodyKeys];
  if (new Set(keys).size !== keys.length) invalid();
  for (const key of keys) parseUncompressedSec1(requireHex(key, 65));
}

type PolicySignature = { key: string; signature: string };

function verifyQuorum(
  signatures: readonly PolicySignature[], pins: readonly string[], threshold: number,
  digest: Uint8Array, seen: Set<string>,
): void {
  if (!Array.isArray(signatures) || signatures.length < threshold || signatures.length > MAX_AUTHORITIES) invalid();
  let approvals = 0;
  for (const signature of signatures) {
    assertExactObjectKeys(signature, ["key", "signature"], "ReleasePolicyInvalid");
    const { key } = signature;
    if (seen.has(key)) invalid();
    verifyP256Prehash(requireHex(key, 65), digest, requireHex(signature.signature, 64));
    seen.add(key);
    if (pins.includes(key)) approvals++;
  }
  if (approvals < threshold) invalid();
}

/** Verify the policy's domain and both signature quorums against pinned keys. */
export function authenticateNitroPolicy(text: string, trust: NitroTrust) {
  const { policy, signatures, custodySignatures } = parseStrictJson<{
    policy: NitroPolicy;
    signatures: readonly PolicySignature[];
    custodySignatures: readonly PolicySignature[];
  }>(text, POLICY_ENVELOPE_KEYS);
  assertExactObjectKeys(policy, POLICY_KEYS, "ReleasePolicyInvalid");
  if (policy.version !== 1 || policy.network !== trust.network ||
      policy.securityDomainId !== trust.securityDomainId ||
      policy.noteSeedCommitment !== trust.noteSeedCommitment || typeof policy.recoveryOnly !== "boolean" ||
      canonicalizeJsonValue(policy.publications) !== canonicalizeJsonValue(trust.publications)) invalid();
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
    assertExactObjectKeys(target.pcrs, ["0", "1", "2", "3", "4"], "ReleasePolicyInvalid");
    for (const pcr of Object.values(target.pcrs)) checkDigest(pcr, 48);
  }
  const digest = nitroPolicySigningDigest(policy);
  const seen = new Set<string>();
  verifyQuorum(signatures, trust.keys, trust.threshold, digest, seen);
  verifyQuorum(custodySignatures, trust.custodyKeys, CUSTODY_QUORUM, nitroCustodySigningDigest(policy), seen);
  const digestHex = encodeLowerHex(digest);
  return {
    policy, signatures, custodySignatures, validFrom, expiresAt,
    checkpoint: Object.freeze({
      sequence: policy.sequence, digest: digestHex,
      minimumCustodyEpoch: policy.minimumCustodyEpoch, recoveryOnly: policy.recoveryOnly,
    }),
  };
}

type VerifiedPolicy = ReturnType<typeof authenticateNitroPolicy>;

function verifySignedPolicy(text: string, trust: NitroTrust): VerifiedPolicy {
  const verified = authenticateNitroPolicy(text, trust);
  const anchor = decodeDecimalU64(trust.minimumSequence);
  const sequence = decodeDecimalU64(verified.policy.sequence);
  if ((sequence === anchor && verified.checkpoint.digest !== trust.minimumPolicyDigest) ||
      (sequence === anchor + 1n && verified.policy.previousPolicyDigest !== trust.minimumPolicyDigest)) invalid();
  return verified;
}

function requirePolicyPins({ policy }: VerifiedPolicy, trust: NitroTrust): void {
  if (decodeDecimalU64(policy.sequence) < decodeDecimalU64(trust.minimumSequence) ||
      decodeDecimalU64(policy.minimumCustodyEpoch) < decodeDecimalU64(trust.minimumCustodyEpoch) ||
      (trust.recoveryOnly && !policy.recoveryOnly)) invalid();
}

function requireCurrent(verified: VerifiedPolicy, trust: NitroTrust, now: bigint): void {
  requirePolicyPins(verified, trust);
  if (now < verified.validFrom || now >= verified.expiresAt) invalid();
}

export function verifyNitroPolicy(text: string, trust: NitroTrust, now: bigint): VerifiedPolicy {
  const verified = verifySignedPolicy(text, trust);
  requireCurrent(verified, trust, now);
  return verified;
}

/** Reconcile the mirror with the exact policy already published by the primary. */
export function verifyNitroMirrorPolicy(text: string, primary: string, trust: NitroTrust, now: bigint): VerifiedPolicy {
  if (text !== primary) throw new DecryptionServiceError("ReleasePolicyInvalid", "mirror the primary's exact signed policy file");
  return verifyStoredNitroPolicy(text, trust, now);
}

/** Authenticate an already published head, including after its expiry. */
export function verifyStoredNitroPolicy(text: string, trust: NitroTrust, now: bigint): VerifiedPolicy {
  const verified = verifySignedPolicy(text, trust);
  requirePolicyPins(verified, trust);
  if (now < verified.validFrom) invalid();
  return verified;
}

function revision({ checkpoint, policy }: VerifiedPolicy): NitroPolicyRevision {
  return Object.freeze({ checkpoint, previousPolicyDigest: policy.previousPolicyDigest });
}

function requireSuccessor(prior: VerifiedPolicy, next: VerifiedPolicy): void {
  if (decodeDecimalU64(next.policy.sequence) !== decodeDecimalU64(prior.policy.sequence) + 1n ||
      !followsCheckpoint(prior.checkpoint, revision(next))) invalid();
  const priorRecords = new Map(prior.policy.targets.map(target => [target.custodyEpoch, target.custodyDigest]));
  if (next.policy.targets.some(target => priorRecords.has(target.custodyEpoch) &&
      priorRecords.get(target.custodyEpoch) !== target.custodyDigest)) invalid();
}

/** The mirror must serve the primary's revision or its exact predecessor. */
export function verifyPublishedNitroPolicy([primaryText, mirrorText]: readonly [string, string], trust: NitroTrust, now: bigint) {
  const primary = verifySignedPolicy(primaryText, trust);
  const mirror = verifySignedPolicy(mirrorText, trust);
  const agreed = primary.checkpoint.digest === mirror.checkpoint.digest;
  if (!agreed) requireSuccessor(mirror, primary);
  requireCurrent(primary, trust, now);
  const { policy, checkpoint, validFrom, expiresAt } = primary;
  const update: NitroPolicyUpdate = Object.freeze([revision(primary), revision(mirror)] as const);
  return { policy, checkpoint, validFrom, expiresAt, agreed, update, sameEnvelope: primaryText === mirrorText };
}

function requireSameTrustDomain(first: NitroTrust, second: NitroTrust): void {
  if (first.network !== second.network || first.securityDomainId !== second.securityDomainId ||
      first.noteSeedCommitment !== second.noteSeedCommitment ||
      canonicalizeJsonValue(first.publications) !== canonicalizeJsonValue(second.publications)) invalid();
}

/** The independently distributed incoming pins start at the transition revision. */
export function requireNitroTrustTransition(from: NitroTrust, to: NitroTrust, sequence: string): void {
  requireSameTrustDomain(from, to);
  if (to.minimumSequence !== sequence ||
      decodeDecimalU64(sequence) <= decodeDecimalU64(from.minimumSequence) ||
      decodeDecimalU64(to.minimumCustodyEpoch) < decodeDecimalU64(from.minimumCustodyEpoch) ||
      (from.recoveryOnly && !to.recoveryOnly)) invalid();
}

/** Check an authenticated candidate against the predecessor before writing against its S3 ETag. */
export function nextNitroPublication(
  next: VerifiedPolicy, previous: string | undefined, trust: NitroTrust, previousTrust = trust,
): boolean {
  if (previous === undefined) {
    if (next.policy.sequence !== "1") invalid();
    return true;
  }
  const { policy } = parseStrictJson<{ policy: NitroPolicy }>(previous, POLICY_ENVELOPE_KEYS);
  requireSameTrustDomain(previousTrust, trust);
  const priorTrust = encodeLowerHex(nitroPolicySigningDigest(policy)) === next.checkpoint.digest ? trust : previousTrust;
  const prior = verifySignedPolicy(previous, priorTrust);
  if (prior.checkpoint.digest === next.checkpoint.digest) return false;
  requireSuccessor(prior, next);
  return true;
}

export function requireRetirementPolicy(
  { policy, sameEnvelope }: ReturnType<typeof verifyPublishedNitroPolicy>, replacementEpoch: string, custodyDigest: string,
) {
  if (!sameEnvelope || policy.action !== "activate" ||
      decodeDecimalU64(policy.minimumCustodyEpoch) < decodeDecimalU64(replacementEpoch) ||
      !policy.targets.some(target => target.custodyEpoch === replacementEpoch && target.custodyDigest === custodyDigest)) invalid();
}

function followsCheckpoint(
  current: NitroPolicyCheckpoint | undefined, { checkpoint: next, previousPolicyDigest }: NitroPolicyRevision,
): boolean {
  if (typeof next.recoveryOnly !== "boolean") return false;
  if (!current) return true;
  if (typeof current.recoveryOnly !== "boolean" || (current.recoveryOnly && !next.recoveryOnly)) return false;
  const nextSequence = decodeDecimalU64(next.sequence);
  const currentSequence = decodeDecimalU64(current.sequence);
  if (decodeDecimalU64(next.minimumCustodyEpoch) < decodeDecimalU64(current.minimumCustodyEpoch)) return false;
  if (nextSequence === currentSequence) {
    return next.digest === current.digest && next.minimumCustodyEpoch === current.minimumCustodyEpoch &&
      next.recoveryOnly === current.recoveryOnly;
  }
  if (nextSequence === currentSequence + 1n) return previousPolicyDigest === current.digest;
  return nextSequence > currentSequence;
}

/** Checks both authenticated heads against the checkpoint inside the atomic write. */
export function advancesNitroPolicy(current: NitroPolicyCheckpoint | undefined, [primary, mirror]: NitroPolicyUpdate): boolean {
  if (current !== undefined && !isValidNitroPolicyCheckpoint(current)) return false;
  return followsCheckpoint(current, primary) &&
    (!current || decodeDecimalU64(mirror.checkpoint.sequence) < decodeDecimalU64(current.sequence) ||
      followsCheckpoint(current, mirror));
}
