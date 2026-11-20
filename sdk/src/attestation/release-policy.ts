import {
  API_VERSION,
  EXPECTED_TURNKEY_TRUST_ROOT_ID,
} from "../protocol/constants.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import { releasePolicyDigest } from "../protocol/digest.js";
import { decodeDecimalU64 } from "../protocol/decimal.js";
import { decodeLowerHex } from "../protocol/hex.js";
import { DecryptionServiceError } from "../protocol/error.js";
import type {
  Network,
  PinnedReleaseAuthorities,
  ServiceInfo,
  SignedReleasePolicy,
} from "../protocol/types.js";
import { SERVICE_PROOF_TYPE } from "../protocol/decryption.js";
import { verifyP256Prehash } from "../crypto/p256.js";

export function policySigningDigest(policy: unknown): Uint8Array {
  return releasePolicyDigest(new TextEncoder().encode(canonicalizeJsonValue(policy)));
}

/**
 * Accepts `signed` only for `network`, at a threshold of `authorities`, while
 * `nowMs` is inside its validity window. Mirrors `verify_signed_release_policy`
 * in `protocol/`, check for check.
 */
export function verifySignedReleasePolicy(
  signed: SignedReleasePolicy,
  authorities: PinnedReleaseAuthorities,
  network: Network,
  nowMs: bigint,
): void {
  if (signed.policy.version !== API_VERSION) {
    throw new DecryptionServiceError("UnsupportedVersion");
  }
  if (signed.policy.network !== network) {
    throw new DecryptionServiceError("NetworkMismatch");
  }
  const { threshold, keys } = authorities;
  if (!Number.isSafeInteger(threshold) || threshold < 1 || threshold > 255 ||
      !Array.isArray(keys) || threshold > keys.length) {
    throw new DecryptionServiceError("ReleasePolicyInvalid");
  }
  if (signed.authoritySetId !== authorities.authoritySetId) {
    throw new DecryptionServiceError("ReleasePolicyInvalid");
  }
  if (signed.policy.turnkeyTrustRootId !== EXPECTED_TURNKEY_TRUST_ROOT_ID) {
    throw new DecryptionServiceError("ReleasePolicyInvalid");
  }
  if (
    decodeDecimalU64(signed.policy.revocationEpoch) <
    decodeDecimalU64(authorities.minimumRevocationEpoch)
  ) {
    throw new DecryptionServiceError("ReleasePolicyInvalid");
  }
  const validFrom = decodeDecimalU64(signed.policy.validFromMs);
  const expires = decodeDecimalU64(signed.policy.expiresAtMs);
  if (nowMs < validFrom || nowMs > expires) {
    throw new DecryptionServiceError("ExpiredRequest");
  }
  if (signed.signatures.length === 0) {
    throw new DecryptionServiceError("ReleasePolicyInvalid");
  }

  const byId = new Map<string, Uint8Array>();
  const publicKeys = new Set<string>();
  for (const key of keys) {
    if (byId.has(key.keyId) || publicKeys.has(key.publicKey)) {
      throw new DecryptionServiceError("ReleasePolicyInvalid");
    }
    const publicKey = decodeLowerHex(key.publicKey);
    publicKeys.add(key.publicKey);
    byId.set(key.keyId, publicKey);
  }

  const seen = new Set<string>();
  const duplicates = new Set<string>();
  for (const signature of signed.signatures) {
    if (seen.has(signature.keyId)) duplicates.add(signature.keyId);
    seen.add(signature.keyId);
  }

  const digest = policySigningDigest(signed.policy);
  let accepted = 0;
  for (const signature of signed.signatures) {
    if (duplicates.has(signature.keyId)) continue;
    const publicKey = byId.get(signature.keyId);
    if (!publicKey) continue;
    verifyP256Prehash(publicKey, digest, decodeLowerHex(signature.signature));
    accepted += 1;
  }
  if (accepted < threshold) {
    throw new DecryptionServiceError("ReleasePolicyInvalid");
  }
}

/**
 * Binds every security field of `/v1/info` to a policy that has already
 * verified for the client's network, so discovery must name that network too.
 */
export function bindDiscoveryToPolicy(
  info: ServiceInfo,
  signed: SignedReleasePolicy,
): void {
  const policy = signed.policy;
  if (info.network !== policy.network) {
    throw new DecryptionServiceError("NetworkMismatch");
  }
  if (info.version !== API_VERSION) {
    throw new DecryptionServiceError("UnsupportedVersion");
  }
  if (info.proof_type !== SERVICE_PROOF_TYPE) {
    throw new DecryptionServiceError("ReleaseBindingMismatch");
  }
  if (info.release_id !== policy.releaseId) {
    throw new DecryptionServiceError("ReleaseBindingMismatch");
  }
  if (info.security_domain_id !== policy.securityDomainId) {
    throw new DecryptionServiceError("ReleaseBindingMismatch");
  }
  if (info.quorum_key_id !== policy.quorumKeyId) {
    throw new DecryptionServiceError("ReleaseBindingMismatch");
  }
  if (info.quorum_key_epoch !== policy.quorumKeyEpoch) {
    throw new DecryptionServiceError("QuorumKeyEpochMismatch");
  }
  if (info.quorum_public_key !== policy.quorumPublicKey) {
    throw new DecryptionServiceError("ReleaseBindingMismatch");
  }
  if (!policy.acceptedManifestDigests.includes(info.manifest_digest)) {
    throw new DecryptionServiceError("ReleaseBindingMismatch");
  }
  if (!policy.acceptedExecutableDigests.includes(info.executable_digest)) {
    throw new DecryptionServiceError("ReleaseBindingMismatch");
  }
  if (
    info.supported_operations.length !== policy.allowedOperations.length ||
    info.supported_operations.some(
      (operation, index) => operation !== policy.allowedOperations[index],
    )
  ) {
    throw new DecryptionServiceError("ReleaseBindingMismatch");
  }
  if (
    decodeDecimalU64(info.max_encrypted_request_bytes) !==
      BigInt(policy.maxEncryptedRequestBytes) ||
    decodeDecimalU64(info.max_encrypted_response_bytes) !==
      BigInt(policy.maxEncryptedResponseBytes)
  ) {
    throw new DecryptionServiceError("ReleaseBindingMismatch");
  }
}
