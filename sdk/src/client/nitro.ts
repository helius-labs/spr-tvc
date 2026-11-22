import { connectNitroTarget, nitroTransport } from "../attestation/nitro-connection.js";
import { indexedDbNitroPolicyStore } from "../attestation/nitro-checkpoint.js";
import {
  advancesNitroPolicy, validateNitroTrust,
  type NitroPolicyCheckpoint, type NitroPolicyStore, type NitroTrust,
} from "../attestation/nitro-policy.js";
import { readPublishedNitroPolicy } from "../attestation/nitro-publication.js";
import type { ConnectedTvcRuntime } from "../connection/connect.js";
import { requireCurrentReleasePolicy } from "../connection/operations.js";
import { awaitWithSignal } from "../connection/request.js";
import { sessionFromConnector } from "../connection/session.js";
import { DecryptionServiceError } from "../protocol/error.js";
import { genesisHashForNetwork } from "../protocol/network.js";
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
const ATTESTATION_STAGGER_MS = 200;
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
        !advancesNitroPolicy(await awaitWithSignal(store.current(), signal), checkpoint) ||
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
    // The signed policy advances trust even if every listed replica is offline.
    await accept(checkpoint, signal);
    currentTime();
    if (policy.action === "revoke") throw new DecryptionServiceError("ReleasePolicyRevoked");
    const count = policy.targets.length;
    const start = next % count;
    const race = new AbortController();
    const probeSignal = AbortSignal.any([signal, race.signal]);
    async function probe(offset: number, previousFailure?: Promise<void>) {
      const index = (start + offset) % count;
      if (previousFailure) {
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          const scheduled = new Promise<void>(resolve => {
            timer = setTimeout(resolve, offset * ATTESTATION_STAGGER_MS);
          });
          await awaitWithSignal(Promise.race([previousFailure, scheduled]), probeSignal);
        } finally {
          clearTimeout(timer);
        }
      }
      probeSignal.throwIfAborted();
      const connected = await connectNitroTarget(policy.targets[index]!, trust, probeSignal);
      const now = currentTime();
      const sessionExpiry = now + CONNECTION_TTL_MS;
      const policyExpiry = sessionExpiry < expiresAt ? sessionExpiry : expiresAt - 1n;
      const { certificateValidFromMs, certificateValidThroughMs } = connected;
      const window = {
        releasePolicyValidFromMs: validFrom > certificateValidFromMs ? validFrom : certificateValidFromMs,
        releasePolicyExpiresAtMs: policyExpiry < certificateValidThroughMs ? policyExpiry : certificateValidThroughMs,
      };
      requireCurrentReleasePolicy(window, now);
      return { connected, window, index };
    }

    let previousFailure: Promise<void> | undefined;
    const candidates = policy.targets.map((_, offset) => {
      const candidate = probe(offset, previousFailure);
      previousFailure = new Promise(resolve => { void candidate.catch(() => resolve()); });
      return candidate;
    });
    const { connected: { endpoint, info, proofKey }, index, window } = await Promise.any(candidates)
      .catch(() => {
        signal.throwIfAborted();
        currentTime();
        throw new DecryptionServiceError("BootProofUnverified", "no authorized Nitro replica reachable");
      })
      .finally(() => race.abort());
    signal.throwIfAborted();
    requireCurrentReleasePolicy(window, currentTime());
    next = index + 1;
    return {
      backend: { endpoint },
      info,
      transport: nitroTransport,
      responseTimeoutMs: RESPONSE_TIMEOUT_MS,
      recoveryOnly: policy.recoveryOnly,
      nowMs: clock,
      ...window,
      async requireCurrentCheckpoint(signal) {
        const current = await awaitWithSignal(store.current(), signal);
        if (current?.digest !== checkpoint.digest || current.sequence !== checkpoint.sequence ||
            current.minimumCustodyEpoch !== checkpoint.minimumCustodyEpoch ||
            current.recoveryOnly !== checkpoint.recoveryOnly) {
          throw new DecryptionServiceError("ReleasePolicySuperseded");
        }
      },
      trustVerifier: {
        async verifyOperationAppProof(proof) {
          if (proof.publicKey !== proofKey) throw new DecryptionServiceError("BootProofUnverified");
        },
      },
    };
  });
  return decryptionServiceFromSession(session, genesisHashForNetwork(trust.network), { requestTimeoutMs: config.requestTimeoutMs, retryPublicKeys: true });
}
