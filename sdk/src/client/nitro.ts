import { connectNitroTarget, nitroTransport } from "../attestation/nitro-connection.js";
import { indexedDbNitroPolicyStore } from "../attestation/nitro-checkpoint.js";
import {
  advancesNitroPolicy, validateNitroTrust,
  type NitroPolicyCheckpoint, type NitroPolicyStore, type NitroTrust,
} from "../attestation/nitro-policy.js";
import { readPublishedNitroPolicy } from "../attestation/nitro-publication.js";
import type { ConnectedTvcRuntime } from "../connection/connect.js";
import { awaitWithSignal } from "../connection/request.js";
import { sessionFromConnector } from "../connection/session.js";
import { DecryptionServiceError } from "../protocol/error.js";
import { decryptionServiceFromSession, type DecryptionService } from "./decryption.js";

export { advancesNitroPolicy } from "../attestation/nitro-policy.js";
export type { NitroPolicy, NitroPolicyCheckpoint, NitroPolicyStore, NitroTarget, NitroTrust } from "../attestation/nitro-policy.js";

export type NitroDecryptionServiceConfig = {
  readonly trust: NitroTrust;
  /** Defaults to IndexedDB when available. Other runtimes supply a durable store. */
  readonly policyStore?: NitroPolicyStore;
  readonly requestTimeoutMs?: number;
};

const CONNECTION_TTL_MS = 60_000n;
const RESPONSE_TIMEOUT_MS = 12_000;
const clock = () => BigInt(Date.now());

/** Uses an independently pinned release quorum and attests the selected Nitro replica. */
export function createNitroDecryptionService(config: NitroDecryptionServiceConfig): DecryptionService {
  const trust = structuredClone(config.trust);
  validateNitroTrust(trust);
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
    const { policy, checkpoint, validFrom, expiresAt } = await readPublishedNitroPolicy(trust, signal);
    function currentTime(): bigint {
      const now = clock();
      if (now < validFrom || now >= expiresAt) throw new DecryptionServiceError("ReleasePolicyInvalid");
      return now;
    }
    if (!advancesNitroPolicy(latest, checkpoint) ||
        !advancesNitroPolicy(await awaitWithSignal(store.current(), signal), checkpoint)) {
      throw new DecryptionServiceError("ReleasePolicyInvalid", "policy rollback");
    }
    currentTime();
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
        connected = await connectNitroTarget(target, trust, signal);
      } catch {
        signal.throwIfAborted();
        continue;
      }
      const { endpoint, info, proofKey } = connected;
      currentTime();
      await accept(checkpoint, signal);
      const now = currentTime();
      next = index + 1;
      const sessionExpiry = now + CONNECTION_TTL_MS;
      return {
        backend: { endpoint },
        info,
        transport: nitroTransport,
        responseTimeoutMs: RESPONSE_TIMEOUT_MS,
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
  return decryptionServiceFromSession(session, { requestTimeoutMs: config.requestTimeoutMs, retryPublicKeys: true });
}
