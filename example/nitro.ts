import { lstat } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import { setTimeout } from "node:timers/promises";
import type { ShieldedAddress } from "@heliuslabs/spr";
import { DecryptionServiceError } from "@heliuslabs/spr-decryption-service";
import {
  advancesNitroPolicy, createNitroDecryptionService, type NitroPolicyCheckpoint, type NitroPolicyStore, type NitroTrust,
} from "@heliuslabs/spr-decryption-service/nitro";
import { isValidNitroPolicyCheckpoint, sameNitroCheckpoint, validateNitroTrust } from "../sdk/src/attestation/nitro-policy.js";
import { readPublishedNitroPolicy } from "../sdk/src/attestation/nitro-publication.js";
import { decodeDecimalU64 } from "../sdk/src/protocol/decimal.js";
import { DecryptionServiceError as PolicyReadError } from "../sdk/src/protocol/error.js";
import { requireHex } from "../sdk/src/protocol/hex.js";
import { parseStrictJson } from "../sdk/src/protocol/json.js";
import { readBoundedDocument } from "../xtask/read-document.js";

export function checkpointStore(path: string, trust: Pick<NitroTrust, "network" | "securityDomainId">) {
  if (!path || path === ":memory:") throw new Error("use a persistent checkpoint file");
  const db = new DatabaseSync(path, { timeout: 1_000 });
  const scope = `${trust.network}/${trust.securityDomainId}`;
  try {
    db.exec(`PRAGMA synchronous = FULL;
    BEGIN IMMEDIATE;
    CREATE TABLE IF NOT EXISTS checkpoints (
      scope TEXT PRIMARY KEY,
      sequence TEXT NOT NULL,
      digest TEXT NOT NULL,
      minimumCustodyEpoch TEXT NOT NULL,
      recoveryOnly INTEGER NOT NULL CHECK (recoveryOnly IN (0, 1)),
      revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
    ) STRICT;`);
    if (!db.prepare("PRAGMA table_info(checkpoints)").all().some(column => column.name === "revoked")) {
      db.exec("ALTER TABLE checkpoints ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))");
    }
    db.exec("COMMIT");
  } catch (error) {
    db.close();
    throw error;
  }
  const read = db.prepare("SELECT sequence, digest, minimumCustodyEpoch, recoveryOnly, revoked FROM checkpoints WHERE scope = ?");
  const save = db.prepare(`INSERT INTO checkpoints (scope, sequence, digest, minimumCustodyEpoch, recoveryOnly, revoked)
    VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(scope) DO UPDATE SET sequence = excluded.sequence, digest = excluded.digest,
      minimumCustodyEpoch = excluded.minimumCustodyEpoch, recoveryOnly = excluded.recoveryOnly, revoked = excluded.revoked`);
  function current(): NitroPolicyCheckpoint | undefined {
    const row = read.get(scope);
    if (row === undefined) return undefined;
    const { revoked, recoveryOnly, ...fields } = row;
    const checkpoint = { ...fields, recoveryOnly: recoveryOnly === 1, ...(revoked === 1 ? { revoked: true } : {}) };
    if ((recoveryOnly !== 0 && recoveryOnly !== 1) || (revoked !== 0 && revoked !== 1) || !isValidNitroPolicyCheckpoint(checkpoint)) {
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
        if (accepted && !sameNitroCheckpoint(previous, next)) {
          save.run(scope, next.sequence, next.digest, next.minimumCustodyEpoch, Number(next.recoveryOnly), Number(next.revoked === true));
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
  return published.sameEnvelope && sameNitroCheckpoint(accepted, published.checkpoint);
}

type Custody = { custodyEpoch: string; custodyDigest: string };

export function requireOriginalPolicy(
  published: VerifiedPublication,
  accepted: NitroPolicyCheckpoint | undefined,
  replacement?: bigint,
): Custody {
  const { policy } = published;
  const first = policy.targets[0];
  if (!acceptedPolicy(published, accepted) || policy.action !== "activate" || policy.recoveryOnly || !first ||
      (replacement !== undefined && BigInt(first.custodyEpoch) >= replacement) ||
      policy.targets.some(({ custodyEpoch, custodyDigest }) => custodyEpoch !== first.custodyEpoch || custodyDigest !== first.custodyDigest)) {
    throw new Error("start with both buckets serving the accepted policy for the original custody epoch only");
  }
  return { custodyEpoch: first.custodyEpoch, custodyDigest: first.custodyDigest };
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

type RetirementScope = Pick<NitroTrust, "network" | "securityDomainId"> & {
  original: Custody;
  replacementEpoch: string;
  transferredAt: bigint;
};

export function parseRetirementReport(text: string, scope: RetirementScope) {
  const report = parseStrictJson<{
    retirementObservedAtMs: string;
    retired: Custody & Pick<NitroTrust, "network" | "securityDomainId"> & { publishedAtMs: string };
    replacement: Custody & {
      walletPolicyDigest: string;
      replacementBootstrap: { bootedAtMs: string; bootKeyId: string; slots: number[] };
    };
  }>(text);
  const { retired, replacement } = report;
  if (!retired || !replacement || retired.network !== scope.network || retired.securityDomainId !== scope.securityDomainId ||
      retired.custodyEpoch !== scope.original.custodyEpoch || retired.custodyDigest !== scope.original.custodyDigest ||
      replacement.custodyEpoch !== scope.replacementEpoch) {
    throw new Error("retirement report does not match the transfer's custody domain and epochs");
  }
  const published = decodeDecimalU64(retired.publishedAtMs);
  const observed = decodeDecimalU64(report.retirementObservedAtMs);
  if (published <= scope.transferredAt || observed < published) {
    throw new Error("expected retirement to be published after the confirmed transfer and before verification");
  }
  const { custodyDigest, walletPolicyDigest, replacementBootstrap: { bootedAtMs, bootKeyId, slots } } = replacement;
  requireHex(custodyDigest, 32);
  requireHex(walletPolicyDigest, 32);
  requireHex(bootKeyId, 32);
  if (decodeDecimalU64(bootedAtMs) <= observed || !Array.isArray(slots) ||
      slots.length !== 3 || new Set(slots).size !== 3 || slots.some(slot => !Number.isInteger(slot) || slot < 1 || slot > 6)) {
    throw new Error("expected a retirement report for a later boot from three custody slots");
  }
  return { custodyDigest, walletPolicyDigest, bootKeyId };
}

export function requireRetirementPolicy(published: VerifiedPublication, retired: ReturnType<typeof parseRetirementReport>) {
  if (published.checkpoint.digest !== retired.walletPolicyDigest ||
      published.policy.targets.some(target => target.custodyDigest !== retired.custodyDigest)) {
    throw new Error("replacement policy differs from the verified retirement report");
  }
}

export async function waitForRetirement(path: string, scope: RetirementScope) {
  const signal = AbortSignal.timeout(60 * 60_000);
  for (;;) {
    signal.throwIfAborted();
    const text = await readBoundedDocument(path, 256 * 1024).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
    });
    signal.throwIfAborted();
    if (text !== undefined) return parseRetirementReport(text, scope);
    await setTimeout(2_000, undefined, { signal });
  }
}

async function devnetTrust(path: string): Promise<NitroTrust> {
  const trust = parseStrictJson<NitroTrust>(await readBoundedDocument(path, 32 * 1024));
  if (trust?.network !== "devnet") throw new Error("the Nitro rehearsal requires devnet wallet trust");
  validateNitroTrust(trust);
  return trust;
}

export function requireCurrentPolicy(
  published: VerifiedPublication,
  current: NitroPolicyCheckpoint | undefined,
  expected: NitroPolicyCheckpoint,
) {
  if (!acceptedPolicy(published, expected) || !sameNitroCheckpoint(current, expected)) {
    throw new Error("wallet policy changed during the rehearsal");
  }
}

async function checkCurrentPolicy(trust: NitroTrust, store: NitroPolicyStore, expected: NitroPolicyCheckpoint) {
  const published = await readPublishedNitroPolicy(trust, AbortSignal.timeout(5_000));
  requireCurrentPolicy(published, await store.current(), expected);
}

export async function nativeDevnet(walletTrust: string, checkpoint: string, replacement: Replacement) {
  const trust = await devnetTrust(walletTrust);
  const replacementEpoch = "epoch" in replacement ? replacement.epoch : undefined;
  const retirementReport = "epoch" in replacement ? replacement.retirementReport : undefined;
  if (retirementReport) {
    const existing = await lstat(retirementReport).catch((error: NodeJS.ErrnoException) => {
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
  let originalCustody: Custody | undefined;
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
      async prepareTransfer() {
        const published = await readPublishedNitroPolicy(trust, AbortSignal.timeout(5_000));
        const custody = requireOriginalPolicy(
          published, await original.store.current(), replacementEpoch === undefined ? undefined : BigInt(replacementEpoch),
        );
        return async () => {
          await checkCurrentPolicy(trust, original.store, published.checkpoint);
          originalCustody = custody;
        };
      },
      async afterTransfer(oldDestination: ShieldedAddress, confirmedAt: bigint) {
        let retired: Awaited<ReturnType<typeof waitForRetirement>> | undefined;
        if (retirementReport) {
          if (!originalCustody || replacementEpoch === undefined) throw new Error("verify the original custody policy before sending");
          retired = await waitForRetirement(retirementReport, {
            network: trust.network, securityDomainId: trust.securityDomainId,
            original: originalCustody, replacementEpoch, transferredAt: confirmedAt,
          });
        }
        const next = createNitroDecryptionService({
          trust: nextTrust, policyStore: nextStore, ...(retired ? { requiredBootKeyId: retired.bootKeyId } : {}),
        });
        const recipient = oldDestination.solanaAddress();
        const signal = AbortSignal.timeout(5 * 60_000);
        const options = { signal, timeoutMs: 10_000 };
        while (!signal.aborted) {
          try {
            let recoveryCheckpoint: NitroPolicyCheckpoint | undefined;
            if (reader) {
              try {
                await reader.address(recipient, options);
                throw new Error("old domain still serves payment destinations");
              } catch (error) {
                if (!(error instanceof DecryptionServiceError) || error.code !== "ReleasePolicyRecoveryOnly") throw error;
              }
              const oldHead = await readPublishedNitroPolicy(recoveryTrust, signal);
              if (!oldHead.policy.recoveryOnly || !acceptedPolicy(oldHead, await original.store.current())) {
                await setTimeout(2_000, undefined, { signal });
                continue;
              }
              recoveryCheckpoint = oldHead.checkpoint;
            }
            const destination = await next.address(recipient, options);
            const published = await readPublishedNitroPolicy(nextTrust, signal);
            const accepted = await nextStore.current();
            if (accepted && acceptedReplacementPolicy(published, accepted, replacementEpoch)) {
              if (retired) requireRetirementPolicy(published, retired);
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
                  await Promise.all([
                    checkCurrentPolicy(nextTrust, nextStore, accepted),
                    recoveryCheckpoint && checkCurrentPolicy(recoveryTrust, original.store, recoveryCheckpoint),
                  ]);
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
