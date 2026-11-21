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
  readonly pcrs: NitroPcrs;
};

export type NitroPolicy = {
  readonly version: 1;
  readonly network: Network;
  readonly securityDomainId: string;
  readonly noteSeedCommitment: string;
  readonly sequence: string;
  readonly validFromMs: string;
  readonly expiresAtMs: string;
  readonly targets: readonly NitroTarget[];
};

export type NitroTrust = {
  readonly network: Network;
  readonly securityDomainId: string;
  readonly noteSeedCommitment: string;
  readonly minimumSequence: string;
  readonly threshold: number;
  /** Uncompressed SEC1 P-256 public keys pinned by the wallet integrator. */
  readonly keys: readonly string[];
};

export type NitroPolicyCheckpoint = { readonly sequence: string; readonly digest: string };

/**
 * An atomic durable compare-and-set per pinned network and security domain.
 * Accept a higher sequence or the identical checkpoint. Refuse older sequences,
 * the same sequence with a different digest, and writes which cannot persist.
 */
export type NitroPolicyStore = {
  accept(checkpoint: NitroPolicyCheckpoint): Promise<boolean>;
};

const MAX_TARGETS = 8;
const MAX_AUTHORITIES = 8;
const MAX_LIFETIME_MS = 7n * 24n * 60n * 60n * 1000n;
const POLICY_KEYS = [
  "version", "network", "securityDomainId", "noteSeedCommitment", "sequence",
  "validFromMs", "expiresAtMs", "targets",
];
const TARGET_KEYS = ["endpoint", "releaseId", "executableSha256", "pcrs"];
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

export function nitroPolicySigningDigest(policy: NitroPolicy): Uint8Array {
  return sha256(te.encode("SPR/native-nitro/release-policy/v1" + canonicalizeJsonValue(policy)));
}

export function validateNitroTrust(trust: NitroTrust): void {
  if (trust.network !== "devnet" && trust.network !== "mainnet") invalid();
  checkDigest(trust.securityDomainId, 32);
  checkDigest(trust.noteSeedCommitment, 32);
  if (decodeDecimalU64(trust.minimumSequence) < 1n ||
      !Array.isArray(trust.keys) || trust.keys.length > MAX_AUTHORITIES ||
      !Number.isSafeInteger(trust.threshold) || trust.threshold < 2 ||
      trust.threshold > trust.keys.length || new Set(trust.keys).size !== trust.keys.length) invalid();
  for (const key of trust.keys) parseUncompressedSec1(requireHex(key, 65));
}

export function verifyNitroPolicy(
  text: string, trust: NitroTrust, now: bigint,
): { policy: NitroPolicy; checkpoint: NitroPolicyCheckpoint; validFrom: bigint; expiresAt: bigint } {
  const { policy, signatures } = parseStrictJson<{
    policy: NitroPolicy;
    signatures: readonly { key: string; signature: string }[];
  }>(text, ["policy", "signatures"]);
  assertExactObjectKeys(policy, POLICY_KEYS, "ReleasePolicyInvalid");
  if (policy.version !== 1 || policy.network !== trust.network ||
      policy.securityDomainId !== trust.securityDomainId ||
      policy.noteSeedCommitment !== trust.noteSeedCommitment) invalid();
  const sequence = decodeDecimalU64(policy.sequence);
  const validFrom = decodeDecimalU64(policy.validFromMs);
  const expiresAt = decodeDecimalU64(policy.expiresAtMs);
  if (sequence < decodeDecimalU64(trust.minimumSequence) || now < validFrom ||
      now >= expiresAt || expiresAt - validFrom > MAX_LIFETIME_MS) invalid();
  if (!Array.isArray(policy.targets) || policy.targets.length === 0 ||
      policy.targets.length > MAX_TARGETS) invalid();
  const endpoints = new Set<string>();
  for (const target of policy.targets) {
    assertExactObjectKeys(target, TARGET_KEYS, "ReleasePolicyInvalid");
    const endpoint = nitroEndpoint(target.endpoint, policy.network).href;
    if (endpoints.has(endpoint) || typeof target.releaseId !== "string" ||
        !/^[a-z0-9][a-z0-9-]{0,63}$/.test(target.releaseId)) invalid();
    endpoints.add(endpoint);
    checkDigest(target.executableSha256, 32);
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
    checkpoint: { sequence: policy.sequence, digest: encodeLowerHex(digest) },
  };
}

/** Returns true for a new policy or a repeat of the exact same policy. */
export function advancesNitroPolicy(current: NitroPolicyCheckpoint | undefined, next: NitroPolicyCheckpoint): boolean {
  if (!current) return true;
  const nextSequence = decodeDecimalU64(next.sequence);
  const currentSequence = decodeDecimalU64(current.sequence);
  return nextSequence > currentSequence ||
    (nextSequence === currentSequence && next.digest === current.digest);
}
