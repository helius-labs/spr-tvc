import { sha256 } from "@noble/hashes/sha256";
import { verifyNativeNitroEvidence } from "../attestation/boot-proof.js";
import { indexedDbNitroPolicyStore } from "../attestation/nitro-checkpoint.js";
import {
  advancesNitroPolicy, nitroEndpoint, validateNitroTrust, verifyNitroPolicy,
  type NitroPolicyCheckpoint, type NitroPolicyStore, type NitroTarget, type NitroTrust,
} from "../attestation/nitro-policy.js";
import type { ConnectedTvcRuntime } from "../connection/connect.js";
import { endpointUrl, fetchWithSignal, httpError, readBoundedText } from "../connection/http.js";
import { awaitWithSignal } from "../connection/request.js";
import { sessionFromConnector } from "../connection/session.js";
import { parseQosP256Public } from "../crypto/qos.js";
import { API_VERSION, QOS_P256_PUBLIC_LEN } from "../protocol/constants.js";
import { DecryptionServiceError } from "../protocol/error.js";
import { encodeLowerHex, requireHex } from "../protocol/hex.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import { assertExactObjectKeys, parseStrictJson } from "../protocol/json.js";
import { SERVICE_PROOF_TYPE } from "../protocol/decryption.js";
import { SERVICE_INFO_KEYS, type ServiceInfo } from "../protocol/types.js";
import { decryptionServiceFromSession, type DecryptionService } from "./decryption.js";

export { advancesNitroPolicy } from "../attestation/nitro-policy.js";
export type { NitroPolicy, NitroPolicyCheckpoint, NitroPolicyStore, NitroTarget, NitroTrust } from "../attestation/nitro-policy.js";

export type NitroDecryptionServiceConfig = {
  readonly policyUrl: URL;
  readonly trust: NitroTrust;
  /** Defaults to IndexedDB when available. Other runtimes supply a durable store. */
  readonly policyStore?: NitroPolicyStore;
  readonly requestTimeoutMs?: number;
};

const MAX_POLICY_BYTES = 32_768n;
const MAX_DISCOVERY_BYTES = 49_152n;
const MAX_ATTESTATION_BYTES = 16_384;
const CONNECTION_TTL_MS = 60_000n;
const TARGET_TIMEOUT_MS = 3_500;
const te = new TextEncoder();
const transport = {
  async fetch(url: URL, init?: RequestInit) {
    try {
      return await fetch(url, { ...init, cache: "no-store", credentials: "omit", redirect: "error" });
    } catch {
      init?.signal?.throwIfAborted();
      throw new DecryptionServiceError("EndpointUnavailable");
    }
  },
};
const clock = () => BigInt(Date.now());

/** Attests one replica before returning values used to build or sign a request. */
async function connectTarget(target: NitroTarget, trust: NitroTrust, signal: AbortSignal) {
  const endpoint = nitroEndpoint(target.endpoint, trust.network);
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const response = await fetchWithSignal(transport, endpointUrl(endpoint, "/v1/nitro/attestation"), {
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
    verifyNativeNitroEvidence(requireHex(evidence), nonce, binding, target.pcrs, clock()), signal,
  );
  return { endpoint, info, proofKey };
}

/** Uses an independently pinned release quorum and attests the selected Nitro replica. */
export function createNitroDecryptionService(config: NitroDecryptionServiceConfig): DecryptionService {
  const trust = structuredClone(config.trust);
  validateNitroTrust(trust);
  const policyUrl = nitroEndpoint(config.policyUrl.href, trust.network);
  const store = config.policyStore ?? indexedDbNitroPolicyStore(trust);
  let latest: NitroPolicyCheckpoint | undefined;
  let next = 0;

  async function accept(checkpoint: NitroPolicyCheckpoint, signal: AbortSignal): Promise<void> {
    signal.throwIfAborted();
    if (!advancesNitroPolicy(latest, checkpoint) ||
        !await awaitWithSignal(store.accept(checkpoint), signal) ||
        !advancesNitroPolicy(latest, checkpoint)) {
      throw new DecryptionServiceError("ReleasePolicyInvalid", "policy rollback or checkpoint unavailable");
    }
    latest = checkpoint;
  }

  const session = sessionFromConnector(async (signal): Promise<ConnectedTvcRuntime> => {
    const response = await fetchWithSignal(transport, policyUrl, undefined, signal);
    if (!response.ok) throw httpError(response, "ReleasePolicyInvalid");
    const text = await readBoundedText(response, MAX_POLICY_BYTES, signal);
    const { policy, checkpoint, validFrom, expiresAt } = verifyNitroPolicy(text, trust, clock());
    if (!advancesNitroPolicy(latest, checkpoint)) throw new DecryptionServiceError("ReleasePolicyInvalid", "policy rollback");
    if (policy.action === "revoke") {
      await accept(checkpoint, signal);
      throw new DecryptionServiceError("ReleasePolicyRevoked");
    }
    const count = policy.targets.length;
    const start = next % count;
    for (let offset = 0; offset < count; offset++) {
      const index = (start + offset) % count;
      const target = policy.targets[index]!;
      let connected;
      try {
        connected = await connectTarget(target, trust, AbortSignal.any([signal, AbortSignal.timeout(TARGET_TIMEOUT_MS)]));
      } catch {
        signal.throwIfAborted();
        continue;
      }
      const { endpoint, info, proofKey } = connected;
      const qualifiedAt = clock();
      if (qualifiedAt < validFrom || qualifiedAt >= expiresAt) {
        throw new DecryptionServiceError("ReleasePolicyInvalid");
      }
      await accept(checkpoint, signal);
      const now = clock();
      if (now < validFrom || now >= expiresAt) {
        throw new DecryptionServiceError("ReleasePolicyInvalid");
      }
      next = index + 1;
      const sessionExpiry = now + CONNECTION_TTL_MS;
      return {
        backend: { endpoint },
        info,
        transport,
        nowMs: clock,
        releasePolicyValidFromMs: validFrom,
        releasePolicyExpiresAtMs: sessionExpiry < expiresAt ? sessionExpiry : expiresAt - 1n,
        async requireCurrentCheckpoint(signal) {
          const current = await awaitWithSignal(store.current(), signal);
          if (current?.digest !== checkpoint.digest || current.sequence !== checkpoint.sequence ||
              current.minimumCustodyEpoch !== checkpoint.minimumCustodyEpoch) {
            throw new DecryptionServiceError("ReleasePolicySuperseded");
          }
        },
        trustVerifier: {
          async verifyOperationAppProof(proof) {
            if (proof.publicKey !== proofKey) throw new DecryptionServiceError("BootProofUnverified");
          },
        },
      };
    }
    throw new DecryptionServiceError("BootProofUnverified", "no authorized Nitro replica reachable");
  });
  return decryptionServiceFromSession(session, config.requestTimeoutMs);
}
