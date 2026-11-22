import { open, readFile, stat } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import { setTimeout } from "node:timers/promises";
import type { ShieldedAddress } from "@heliuslabs/spr";
import { DecryptionServiceError } from "@heliuslabs/spr-decryption-service";
import {
  advancesNitroPolicy, createNitroDecryptionService, type NitroPolicyCheckpoint, type NitroPolicyStore, type NitroTrust,
} from "@heliuslabs/spr-decryption-service/nitro";
import { isValidNitroPolicyCheckpoint } from "../sdk/src/attestation/nitro-policy.js";
import { readPublishedNitroPolicy } from "../sdk/src/attestation/nitro-publication.js";
import { decodeDecimalU64 } from "../sdk/src/protocol/decimal.js";
import { DecryptionServiceError as PolicyReadError } from "../sdk/src/protocol/error.js";
import { requireHex } from "../sdk/src/protocol/hex.js";
import { parseStrictJson } from "../sdk/src/protocol/json.js";

export function checkpointStore(path: string, trust: Pick<NitroTrust, "network" | "securityDomainId">) {
  if (!path || path === ":memory:") throw new Error("use a persistent checkpoint file");
  const db = new DatabaseSync(path, { timeout: 1_000 });
  const scope = `${trust.network}/${trust.securityDomainId}`;
  db.exec(`PRAGMA synchronous = FULL;
    CREATE TABLE IF NOT EXISTS checkpoints (
      scope TEXT PRIMARY KEY,
      sequence TEXT NOT NULL,
      digest TEXT NOT NULL,
      minimumCustodyEpoch TEXT NOT NULL,
      recoveryOnly INTEGER NOT NULL CHECK (recoveryOnly IN (0, 1))
    ) STRICT;`);
  const read = db.prepare("SELECT sequence, digest, minimumCustodyEpoch, recoveryOnly FROM checkpoints WHERE scope = ?");
  const save = db.prepare(`INSERT INTO checkpoints VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(scope) DO UPDATE SET sequence = excluded.sequence, digest = excluded.digest,
      minimumCustodyEpoch = excluded.minimumCustodyEpoch, recoveryOnly = excluded.recoveryOnly`);
  function current(): NitroPolicyCheckpoint | undefined {
    const row = read.get(scope);
    if (row === undefined) return undefined;
    const checkpoint = { ...row, recoveryOnly: row.recoveryOnly === 1 };
    if ((row.recoveryOnly !== 0 && row.recoveryOnly !== 1) || !isValidNitroPolicyCheckpoint(checkpoint)) {
      throw new DecryptionServiceError("ReleasePolicyInvalid", "checkpoint storage unavailable");
    }
    return checkpoint;
  }
  const store: NitroPolicyStore = {
    async current() { return current(); },
    async accept(update) {
      const next = update[0].checkpoint;
      db.exec("BEGIN IMMEDIATE");
      try {
        const previous = current();
        const accepted = advancesNitroPolicy(previous, update);
        if (accepted && previous?.sequence !== next.sequence) {
          save.run(scope, next.sequence, next.digest, next.minimumCustodyEpoch, Number(next.recoveryOnly));
        }
        db.exec("COMMIT");
        return accepted;
      } catch (error) {
        if (db.isTransaction) db.exec("ROLLBACK");
        throw error;
      }
    },
  };
  return { store, close: () => db.close() };
}

const RETRYABLE_POLICY_ERRORS = new Set(["ReleasePolicyInvalid", "BootProofUnverified", "EndpointUnavailable", "ExpiredRequest"]);

type VerifiedPublication = Pick<Awaited<ReturnType<typeof readPublishedNitroPolicy>>, "sameEnvelope" | "checkpoint" | "policy">;

function acceptedPolicy(
  published: VerifiedPublication,
  accepted: NitroPolicyCheckpoint | undefined,
): boolean {
  return published.sameEnvelope && sameCheckpoint(accepted, published.checkpoint);
}

function sameCheckpoint(accepted: NitroPolicyCheckpoint | undefined, checkpoint: NitroPolicyCheckpoint): boolean {
  return accepted?.sequence === checkpoint.sequence && accepted.digest === checkpoint.digest &&
    accepted.minimumCustodyEpoch === checkpoint.minimumCustodyEpoch && accepted.recoveryOnly === checkpoint.recoveryOnly;
}

export function requireOriginalPolicy(
  published: VerifiedPublication,
  accepted: NitroPolicyCheckpoint | undefined,
  replacement?: bigint,
): void {
  const { policy } = published;
  const epoch = policy.targets[0]?.custodyEpoch;
  if (!acceptedPolicy(published, accepted) || policy.action !== "activate" || policy.recoveryOnly || epoch === undefined ||
      (replacement !== undefined && BigInt(epoch) >= replacement) || policy.targets.some(target => target.custodyEpoch !== epoch)) {
    throw new Error("start with both buckets serving the accepted policy for the original custody epoch only");
  }
}

export function acceptedReplacementPolicy(
  published: VerifiedPublication,
  accepted: NitroPolicyCheckpoint | undefined,
  epoch?: string,
): boolean {
  const { policy } = published;
  return acceptedPolicy(published, accepted) && policy.action === "activate" && !policy.recoveryOnly &&
    (epoch === undefined || policy.targets.every(target => target.custodyEpoch === epoch));
}

type Replacement = { epoch: string; retirementReport?: string } | { walletTrust: string };

export function parseRetirementReport(text: string, transferredAt: bigint) {
  const report = parseStrictJson<{
    retirementObservedAtMs: string;
    replacement: {
      walletPolicyDigest: string;
      replacementBootstrap: { bootedAtMs: string; bootKeyId: string; slots: number[] };
    };
  }>(text);
  const observed = decodeDecimalU64(report.retirementObservedAtMs);
  const { walletPolicyDigest, replacementBootstrap: { bootedAtMs, bootKeyId, slots } } = report.replacement;
  requireHex(walletPolicyDigest, 32);
  requireHex(bootKeyId, 32);
  if (observed < transferredAt || decodeDecimalU64(bootedAtMs) <= observed || !Array.isArray(slots) ||
      slots.length !== 3 || new Set(slots).size !== 3 || slots.some(slot => !Number.isInteger(slot) || slot < 1 || slot > 6)) {
    throw new Error("expected a retirement report for a later boot from three custody slots");
  }
  return { walletPolicyDigest, bootKeyId };
}

async function waitForRetirement(path: string, transferredAt: bigint) {
  const signal = AbortSignal.timeout(60 * 60_000);
  for (;;) {
    signal.throwIfAborted();
    const file = await open(path, "r").catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
    });
    if (file) {
      try {
        const { size } = await file.stat();
        if (size > 256 * 1024) throw new Error("retirement report exceeds 256 KiB");
        return parseRetirementReport(await file.readFile({ encoding: "utf8", signal }), transferredAt);
      } finally {
        await file.close();
      }
    }
    await setTimeout(2_000, undefined, { signal });
  }
}

async function devnetTrust(path: string): Promise<NitroTrust> {
  const trust = JSON.parse(await readFile(path, "utf8")) as NitroTrust;
  if (trust.network !== "devnet") throw new Error("the Nitro rehearsal requires devnet wallet trust");
  return trust;
}

export async function nativeDevnet(walletTrust: string, checkpoint: string, replacement: Replacement) {
  const trust = await devnetTrust(walletTrust);
  const replacementEpoch = "epoch" in replacement ? replacement.epoch : undefined;
  const retirementReport = "epoch" in replacement ? replacement.retirementReport : undefined;
  if (retirementReport) {
    const existing = await stat(retirementReport).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
    });
    if (existing) throw new Error("use a new path for the retirement report");
  }
  if (replacementEpoch !== undefined && (!/^[1-9][0-9]{0,19}$/.test(replacementEpoch) || BigInt(replacementEpoch) > 2n ** 64n - 1n)) {
    throw new Error("set NITRO_REPLACEMENT_EPOCH to a custody epoch");
  }
  const nextTrust = "walletTrust" in replacement
    ? await devnetTrust(replacement.walletTrust)
    : { ...trust, minimumCustodyEpoch: replacement.epoch };
  const seedChanged = "walletTrust" in replacement;
  if (seedChanged && (nextTrust.securityDomainId === trust.securityDomainId ||
      nextTrust.noteSeedCommitment === trust.noteSeedCommitment || nextTrust.recoveryOnly)) {
    throw new Error("seed cutover requires a different domain and seed commitment for new sends");
  }

  const original = checkpointStore(checkpoint, trust);
  let replacementStore: typeof original | undefined;
  function close() {
    replacementStore?.close();
    original.close();
  }
  try {
    if (seedChanged) replacementStore = checkpointStore(checkpoint, nextTrust);
    const recoveryTrust = { ...trust, recoveryOnly: true };
    const service = createNitroDecryptionService({ trust, policyStore: original.store });
    const reader = seedChanged ? createNitroDecryptionService({ trust: recoveryTrust, policyStore: original.store }) : undefined;
    const nextStore = replacementStore?.store ?? original.store;
    return {
      service,
      seedChanged,
      close,
      async beforeSend() {
        const published = await readPublishedNitroPolicy(trust, AbortSignal.timeout(5_000));
        requireOriginalPolicy(published, await original.store.current(), replacementEpoch === undefined ? undefined : BigInt(replacementEpoch));
      },
      async afterTransfer(oldDestination: ShieldedAddress, confirmedAt: bigint) {
        const retired = retirementReport ? await waitForRetirement(retirementReport, confirmedAt) : undefined;
        const next = createNitroDecryptionService({
          trust: nextTrust, policyStore: nextStore, ...(retired ? { requiredBootKeyId: retired.bootKeyId } : {}),
        });
        const recipient = oldDestination.solanaAddress();
        const signal = AbortSignal.timeout(5 * 60_000);
        const options = { signal, timeoutMs: 10_000 };
        while (!signal.aborted) {
          try {
            if (reader) {
              try {
                await reader.address(recipient, options);
                throw new Error("old domain still serves payment destinations");
              } catch (error) {
                if (!(error instanceof DecryptionServiceError) || error.code !== "ReleasePolicyRecoveryOnly") throw error;
              }
              const oldHead = await readPublishedNitroPolicy(recoveryTrust, signal);
              if (!acceptedPolicy(oldHead, await original.store.current())) {
                await setTimeout(2_000, undefined, { signal });
                continue;
              }
            }
            const destination = await next.address(recipient, options);
            const published = await readPublishedNitroPolicy(nextTrust, signal);
            const accepted = await nextStore.current();
            if (accepted && acceptedReplacementPolicy(published, accepted, replacementEpoch)) {
              if (retired && accepted.digest !== retired.walletPolicyDigest) {
                throw new Error("replacement policy differs from the verified retirement report");
              }
              const sameViewingKey = Buffer.from(destination.viewingPublicKey.toBytes()).equals(oldDestination.viewingPublicKey.toBytes());
              const sameNullifierKey = Buffer.from(destination.nullifierPublicKey).equals(oldDestination.nullifierPublicKey);
              if (reader && (sameViewingKey || sameNullifierKey)) {
                throw new Error("replacement domain repeated an old recipient key");
              }
              if (!reader && (!sameViewingKey || !sameNullifierKey)) {
                throw new Error("custody rotation changed the recipient keys");
              }
              return {
                service: reader ?? next,
                bootKeyId: retired?.bootKeyId,
                async requireSamePolicy() {
                  if (!sameCheckpoint(await nextStore.current(), accepted)) {
                    throw new Error("replacement policy changed during the claim");
                  }
                },
              };
            }
          } catch (error) {
            signal.throwIfAborted();
            const attemptTimedOut = error instanceof DOMException && error.name === "TimeoutError";
            const policyUnavailable = (error instanceof DecryptionServiceError || error instanceof PolicyReadError) &&
              RETRYABLE_POLICY_ERRORS.has(error.code);
            if (!attemptTimedOut && !policyUnavailable) throw error;
          }
          await setTimeout(2_000, undefined, { signal });
        }
        throw signal.reason;
      },
    };
  } catch (error) {
    close();
    throw error;
  }
}
