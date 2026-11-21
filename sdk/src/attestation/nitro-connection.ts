import { sha256 } from "@noble/hashes/sha256";
import { endpointUrl, fetchWithSignal, httpError, readBoundedText } from "../connection/http.js";
import { awaitWithSignal } from "../connection/request.js";
import { parseQosP256Public } from "../crypto/qos.js";
import { API_VERSION, QOS_P256_PUBLIC_LEN } from "../protocol/constants.js";
import { SERVICE_PROOF_TYPE } from "../protocol/decryption.js";
import { DecryptionServiceError } from "../protocol/error.js";
import { encodeLowerHex, requireHex } from "../protocol/hex.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import { assertExactObjectKeys, parseStrictJson } from "../protocol/json.js";
import { SERVICE_INFO_KEYS, type ServiceInfo } from "../protocol/types.js";
import { verifyNativeNitroEvidence } from "./boot-proof.js";
import { nitroEndpoint, type NitroTarget, type NitroTrust } from "./nitro-policy.js";

const MAX_DISCOVERY_BYTES = 49_152n;
const MAX_ATTESTATION_BYTES = 16_384;
const TARGET_TIMEOUT_MS = 3_500;
const te = new TextEncoder();
export const nitroTransport = {
  async fetch(url: URL, init?: RequestInit) {
    try {
      return await fetch(url, { ...init, cache: "no-store", credentials: "omit", redirect: "error" });
    } catch {
      init?.signal?.throwIfAborted();
      throw new DecryptionServiceError("EndpointUnavailable");
    }
  },
};

/** Attests one replica before returning values used to build or sign a request. */
export async function connectNitroTarget(target: NitroTarget, trust: NitroTrust, requestSignal?: AbortSignal) {
  const timeout = AbortSignal.timeout(TARGET_TIMEOUT_MS);
  const signal = requestSignal ? AbortSignal.any([requestSignal, timeout]) : timeout;
  const endpoint = nitroEndpoint(target.endpoint, trust.network);
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const response = await fetchWithSignal(nitroTransport, endpointUrl(endpoint, "/v1/nitro/attestation"), {
    method: "POST",
    body: nonce,
    headers: { "Content-Type": "application/octet-stream" },
  }, signal);
  if (!response.ok) throw httpError(response, "BootProofUnverified");
  const { info, evidence } = parseStrictJson<{ info: ServiceInfo; evidence: string }>(
    await readBoundedText(response, MAX_DISCOVERY_BYTES, signal), ["info", "evidence"],
  );
  assertExactObjectKeys(info, SERVICE_INFO_KEYS, "DiscoveryUntrusted");
  if (typeof evidence !== "string" || evidence.length > 2 * MAX_ATTESTATION_BYTES) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  const transportKey = requireHex(info.quorum_public_key, QOS_P256_PUBLIC_LEN);
  const releaseIdentity = sha256(Uint8Array.from([
    ...te.encode("SPR/native-nitro/release/v1"),
    ...requireHex(target.executableSha256, 32),
    ...requireHex(trust.noteSeedCommitment, 32),
  ]));
  if (info.version !== API_VERSION || info.network !== trust.network ||
      info.release_id !== target.releaseId || info.security_domain_id !== trust.securityDomainId ||
      info.executable_digest !== target.executableSha256 ||
      info.manifest_digest !== encodeLowerHex(releaseIdentity) ||
      info.quorum_key_id !== encodeLowerHex(sha256(transportKey)) || info.quorum_key_epoch !== target.custodyEpoch ||
      info.proof_type !== SERVICE_PROOF_TYPE ||
      canonicalizeJsonValue(info.supported_operations) !== '["ServicePublicKeys","ServiceDecrypt"]' ||
      info.max_encrypted_request_bytes !== "262144" || info.max_encrypted_response_bytes !== "262144") {
    throw new DecryptionServiceError("DiscoveryUntrusted");
  }
  parseQosP256Public(transportKey);
  const binding = sha256(te.encode("SPR/native-nitro/discovery/v1" + canonicalizeJsonValue(info)));
  const proofKey = await awaitWithSignal(
    verifyNativeNitroEvidence(requireHex(evidence), nonce, binding, target.pcrs, BigInt(Date.now())), signal,
  );
  return { endpoint, info, proofKey };
}
