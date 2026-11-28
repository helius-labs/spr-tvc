import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";

import {
  MAX_U32,
  MAX_U32_BIGINT,
  SEC1_UNCOMPRESSED_LEN,
  SHA384_LEN,
} from "../wire/constants.js";
import { decodeLowerHex, encodeLowerHex } from "../wire/hex.js";
import { decodeDecimalU64 } from "../wire/decimal.js";
import { DecryptionServiceError } from "../wire/error.js";
import { parseStrictJson } from "../wire/json.js";
import type { ManifestSetPolicy, ReleasePolicy } from "../wire/types.js";
import { parseUncompressedSec1 } from "../crypto/p256.js";
import { decodeBase64, type QosIdentityPcrs } from "./boot-proof.js";
import { qosJsonHash } from "./qos-json.js";
import type { TurnkeyBootProofWire } from "./turnkey.js";

const td = new TextDecoder("utf-8", { fatal: true });
const IDENTITY_PCR_INDICES = [0, 1, 2, 3] as const;

/**
 * Hash of the Boot Proof manifest when the pinned manifest set approved it.
 * The set, the Quorum key, the namespace, and PCR0–3 come from the pin.
 */
export function approvedManifestSha256(
  bootProof: TurnkeyBootProofWire,
  policy: ReleasePolicy,
  pcrs: QosIdentityPcrs,
): string {
  try {
    return encodeLowerHex(approvedDigest(bootProof, policy, pcrs));
  } catch {
    throw new DecryptionServiceError("BootProofUnverified", "manifest");
  }
}

function approvedDigest(
  bootProof: TurnkeyBootProofWire,
  policy: ReleasePolicy,
  pcrs: QosIdentityPcrs,
): Uint8Array {
  const envelope = parseStrictJson<unknown>(td.decode(decodeBase64(bootProof.qosManifestEnvelopeB64)));
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  const record = envelope as Record<string, unknown>;
  const manifest = record.manifest;
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  const digest = qosJsonHash(manifest);
  const body = manifest as Record<string, unknown>;
  if (body.version !== "v2") {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  const pivot = body.pivot as Record<string, unknown> | undefined;
  if (
    !pivot ||
    typeof pivot !== "object" ||
    Array.isArray(pivot) ||
    pivot.debugMode !== false ||
    (pivot.env !== undefined &&
      pivot.env !== null &&
      (typeof pivot.env !== "object" || Array.isArray(pivot.env) || Object.keys(pivot.env).length > 0))
  ) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  if (!sameManifestSet(policy.manifestSet, body.manifestSet)) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  requireApprovals(record.manifestSetApprovals, policy.manifestSet, digest);
  const namespace = body.namespace as Record<string, unknown> | undefined;
  const floor = decodeDecimalU64(policy.minimumManifestNonce);
  if (
    floor > MAX_U32_BIGINT ||
    !namespace ||
    namespace.name !== policy.namespace ||
    nonce(namespace.nonce) < floor ||
    namespace.quorumKey !== policy.quorumPublicKey
  ) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  const enclave = body.enclave as Record<string, unknown> | undefined;
  if (
    !enclave ||
    enclave.pcr0 !== pcrs[0] ||
    enclave.pcr1 !== pcrs[1] ||
    enclave.pcr2 !== pcrs[2] ||
    enclave.pcr3 !== pcrs[3]
  ) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  for (const index of IDENTITY_PCR_INDICES) {
    if (decodeLowerHex(pcrs[index]).length !== SHA384_LEN) {
      throw new DecryptionServiceError("BootProofUnverified");
    }
  }
  return digest;
}

function sameManifestSet(pinned: ManifestSetPolicy, live: unknown): boolean {
  if (!live || typeof live !== "object" || Array.isArray(live)) return false;
  const set = live as Record<string, unknown>;
  const members = set.members;
  if (
    !Array.isArray(members) ||
    members.length !== pinned.members.length ||
    integer(set.threshold) !== pinned.threshold
  ) {
    return false;
  }
  return pinned.members.every((member) =>
    members.some((candidate) => {
      if (!candidate || typeof candidate !== "object") return false;
      const liveMember = candidate as Record<string, unknown>;
      return liveMember.alias === member.alias && liveMember.pubKey === member.publicKey;
    }),
  );
}

function requireApprovals(live: unknown, pinned: ManifestSetPolicy, digest: Uint8Array): void {
  if (!Array.isArray(live)) throw new DecryptionServiceError("BootProofUnverified");
  const seen = new Set<string>();
  let accepted = 0;
  for (const approval of live) {
    if (!approval || typeof approval !== "object") throw new DecryptionServiceError("BootProofUnverified");
    const record = approval as Record<string, unknown>;
    const member = record.member as Record<string, unknown> | undefined;
    if (
      !member ||
      typeof member.alias !== "string" ||
      typeof member.pubKey !== "string" ||
      typeof record.signature !== "string"
    ) {
      throw new DecryptionServiceError("BootProofUnverified");
    }
    const pinnedMember = pinned.members.find(
      (candidate) => candidate.alias === member.alias && candidate.publicKey === member.pubKey,
    );
    if (!pinnedMember || seen.has(pinnedMember.publicKey)) {
      throw new DecryptionServiceError("BootProofUnverified");
    }
    const key = decodeLowerHex(pinnedMember.publicKey);
    verifyManifestApproval(
      key.subarray(SEC1_UNCOMPRESSED_LEN),
      digest,
      decodeLowerHex(record.signature),
    );
    seen.add(pinnedMember.publicKey);
    accepted += 1;
  }
  if (accepted < pinned.threshold) throw new DecryptionServiceError("BootProofUnverified");
}

function nonce(value: unknown): bigint {
  const parsed = integer(value);
  if (parsed === undefined || parsed < 0 || parsed > MAX_U32) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  return BigInt(parsed);
}

function integer(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "string" && /^[0-9]+$/.test(value)) {
    const parsed = Number(value);
    if (Number.isSafeInteger(parsed) && String(parsed) === value.replace(/^0+(?=\d)/, "")) return parsed;
  }
  return undefined;
}

/** QOS stores the operator signature as produced. Normalize S, then check SHA-256 of the manifest hash. */
function verifyManifestApproval(
  publicSec1: Uint8Array,
  digest: Uint8Array,
  signature: Uint8Array,
): void {
  parseUncompressedSec1(publicSec1);
  let normalized;
  try {
    normalized = p256.Signature.fromCompact(signature).normalizeS();
  } catch {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  if (!p256.verify(normalized, sha256(digest), publicSec1, { prehash: false })) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
}
