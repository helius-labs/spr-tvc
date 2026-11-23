import { connectNitroTarget, nitroOperationBinding } from "../attestation/nitro-connection.js";
import { indexedDbNitroPolicyStore } from "../attestation/nitro-checkpoint.js";
import {
  advancesNitroPolicy, sameNitroCheckpoint, validateNitroTrust,
  type NitroPolicyCheckpoint, type NitroPolicyStore, type NitroPolicyUpdate, type NitroTrust,
} from "../attestation/nitro-policy.js";
import { readPublishedNitroPolicy } from "../attestation/nitro-publication.js";
import type { ConnectedTvcRuntime } from "../connection/connect.js";
import { requireCurrentReleasePolicy } from "../connection/operations.js";
import { awaitWithSignal } from "../connection/request.js";
import { sessionFromConnector } from "../connection/session.js";
import { DecryptionServiceError } from "../protocol/error.js";
import { requireHex } from "../protocol/hex.js";
import { genesisHashForNetwork } from "../protocol/network.js";
import { decryptionServiceFromSession, type DecryptionService } from "./decryption.js";

export { advancesNitroPolicy } from "../attestation/nitro-policy.js";
export type { NitroPolicy, NitroPolicyCheckpoint, NitroPolicyRevision, NitroPolicyStore, NitroPolicyUpdate, NitroTarget, NitroTrust } from "../attestation/nitro-policy.js";

export type NitroDecryptionServiceConfig = {
  readonly trust: NitroTrust;
  /** Defaults to IndexedDB when available. Other runtimes supply a durable store. */
  readonly policyStore?: NitroPolicyStore;
  readonly requestTimeoutMs?: number;
  /** Restrict operation sessions to one attested transport key ID. */
  readonly requiredBootKeyId?: string;
};

const CONNECTION_TTL_MS = 60_000;
const RESPONSE_TIMEOUT_MS = 12_000;
const ATTESTATION_STAGGER_MS = 200;
const clock = () => BigInt(Date.now());

/** Uses an independently pinned release quorum and attests the selected Nitro replica. */
export function createNitroDecryptionService(config: NitroDecryptionServiceConfig): DecryptionService {
  const trust = structuredClone(config.trust);
  validateNitroTrust(trust);
  const { requiredBootKeyId } = config;
  if (requiredBootKeyId !== undefined) requireHex(requiredBootKeyId, 32);
  const store = config.policyStore ?? indexedDbNitroPolicyStore(trust);
  let latest: NitroPolicyCheckpoint | undefined;
  let next = 0;

  // An already-started cancelled commit may still advance the durable checkpoint.
  async function accept(update: NitroPolicyUpdate, signal?: AbortSignal): Promise<boolean> {
    signal?.throwIfAborted();
    if (!advancesNitroPolicy(latest, update) ||
        !advancesNitroPolicy(await awaitWithSignal(store.current(), signal), update) ||
        !await awaitWithSignal(store.accept(update), signal) ||
        !advancesNitroPolicy(latest, update)) {
      return false;
    }
    latest = update[0].checkpoint;
    return true;
  }

  function readPolicy(signal?: AbortSignal) {
    let beforeStop: Promise<NitroPolicyCheckpoint | undefined> | undefined;
    let remembered: NitroPolicyCheckpoint | undefined;
    return readPublishedNitroPolicy(trust, signal, async update => {
      if (!update[1]) {
        if (!beforeStop) {
          remembered = latest;
          beforeStop = store.current();
        }
        await beforeStop;
        // An authenticated stop can finish writing after the request is cancelled.
        return accept(update);
      }
      // A stop accepted during this read cannot make a conflicting successor admissible.
      if (!update[0].checkpoint.revoked && beforeStop &&
          (!advancesNitroPolicy(remembered, update) || !advancesNitroPolicy(await beforeStop, update))) return false;
      return accept(update, signal);
    });
  }

  const session = sessionFromConnector(async (signal): Promise<ConnectedTvcRuntime> => {
    const sessionExpiry = clock() + BigInt(CONNECTION_TTL_MS) - 1n;
    const freshnessDeadline = performance.now() + CONNECTION_TTL_MS;
    const policyFreshnessRemainingMs = () => freshnessDeadline - performance.now();
    // The policy advances trust even if every listed replica is offline.
    const { policy, checkpoint, validFrom, expiresAt } = await readPolicy(signal);
    async function requireCurrentCheckpoint(signal?: AbortSignal): Promise<void> {
      const current = await awaitWithSignal(store.current(), signal);
      if (!sameNitroCheckpoint(current, checkpoint) || !sameNitroCheckpoint(latest, checkpoint)) {
        throw new DecryptionServiceError("ReleasePolicySuperseded");
      }
    }
    function currentTime(): bigint {
      const now = clock();
      if (now < validFrom || now >= expiresAt) throw new DecryptionServiceError("ReleasePolicyInvalid");
      if (now > sessionExpiry || policyFreshnessRemainingMs() <= 0) throw new DecryptionServiceError("ExpiredRequest");
      return now;
    }
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
      await requireCurrentCheckpoint(probeSignal);
      currentTime();
      const connected = await connectNitroTarget(policy.targets[index]!, trust, probeSignal);
      if (requiredBootKeyId !== undefined && connected.info.quorum_key_id !== requiredBootKeyId) {
        throw new DecryptionServiceError("BootProofUnverified");
      }
      const now = currentTime();
      const policyExpiry = sessionExpiry < expiresAt ? sessionExpiry : expiresAt - 1n;
      const { certificateValidFromMs, certificateValidThroughMs } = connected;
      const window = {
        releasePolicyValidFromMs: validFrom > certificateValidFromMs ? validFrom : certificateValidFromMs,
        releasePolicyExpiresAtMs: policyExpiry < certificateValidThroughMs ? policyExpiry : certificateValidThroughMs,
        policyFreshnessRemainingMs,
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
    const { connected, index, window } = await Promise.any(candidates)
      .catch(async () => {
        signal.throwIfAborted();
        await requireCurrentCheckpoint(signal);
        currentTime();
        throw new DecryptionServiceError("BootProofUnverified", "no authorized Nitro replica reachable");
      })
      .finally(() => race.abort());
    signal.throwIfAborted();
    await requireCurrentCheckpoint(signal);
    requireCurrentReleasePolicy(window, currentTime());
    next = index + 1;
    return {
      ...nitroOperationBinding(connected),
      responseTimeoutMs: RESPONSE_TIMEOUT_MS,
      nowMs: clock,
      ...window,
      requireCurrentCheckpoint,
      async requirePublishedPolicy(signal, forPayment) {
        await requireCurrentCheckpoint(signal);
        const { policy } = await readPolicy(signal);
        if (policy.action === "revoke") throw new DecryptionServiceError("ReleasePolicyRevoked");
        if (forPayment && policy.recoveryOnly) throw new DecryptionServiceError("ReleasePolicyRecoveryOnly");
        await requireCurrentCheckpoint(signal);
        requireCurrentReleasePolicy(window, clock());
      },
    };
  });
  return decryptionServiceFromSession(session, genesisHashForNetwork(trust.network), { requestTimeoutMs: config.requestTimeoutMs, retryPublicKeys: true });
}
