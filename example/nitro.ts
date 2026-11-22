import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import { setTimeout } from "node:timers/promises";
import type { ShieldedAddress } from "@heliuslabs/spr";
import { DecryptionServiceError } from "@heliuslabs/spr-decryption-service";
import {
  advancesNitroPolicy, createNitroDecryptionService, type NitroPolicyCheckpoint, type NitroPolicyStore, type NitroTrust,
} from "@heliuslabs/spr-decryption-service/nitro";
import { readPublishedNitroPolicy } from "../sdk/src/attestation/nitro-publication.js";
import { DecryptionServiceError as PolicyReadError } from "../sdk/src/protocol/error.js";

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
    const row = read.get(scope) as (Omit<NitroPolicyCheckpoint, "recoveryOnly"> & { recoveryOnly: number }) | undefined;
    return row && { ...row, recoveryOnly: row.recoveryOnly === 1 };
  }
  const store: NitroPolicyStore = {
    async current() { return current(); },
    async accept(next) {
      db.exec("BEGIN IMMEDIATE");
      try {
        const previous = current();
        const accepted = advancesNitroPolicy(previous, next);
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

function acceptedPolicy(
  published: Awaited<ReturnType<typeof readPublishedNitroPolicy>>,
  accepted: NitroPolicyCheckpoint | undefined,
): boolean {
  const { agreed, checkpoint } = published;
  return agreed && accepted?.sequence === checkpoint.sequence && accepted.digest === checkpoint.digest &&
    accepted.minimumCustodyEpoch === checkpoint.minimumCustodyEpoch && accepted.recoveryOnly === checkpoint.recoveryOnly;
}

export function requireOriginalPolicy(
  published: Awaited<ReturnType<typeof readPublishedNitroPolicy>>,
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

type Replacement = { epoch: string } | { walletTrust: string };

async function devnetTrust(path: string): Promise<NitroTrust> {
  const trust = JSON.parse(await readFile(path, "utf8")) as NitroTrust;
  if (trust.network !== "devnet") throw new Error("the Nitro rehearsal requires devnet wallet trust");
  return trust;
}

export async function nativeDevnet(walletTrust: string, checkpoint: string, replacement: Replacement) {
  const trust = await devnetTrust(walletTrust);
  const replacementEpoch = "epoch" in replacement ? replacement.epoch : undefined;
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
    const next = createNitroDecryptionService({ trust: nextTrust, policyStore: nextStore });
    return {
      service,
      seedChanged,
      close,
      async beforeSend() {
        const published = await readPublishedNitroPolicy(trust, AbortSignal.timeout(5_000));
        requireOriginalPolicy(published, await original.store.current(), replacementEpoch === undefined ? undefined : BigInt(replacementEpoch));
      },
      async afterTransfer(oldDestination: ShieldedAddress) {
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
            if (published.policy.action === "activate" && !published.policy.recoveryOnly && acceptedPolicy(published, await nextStore.current())) {
              if (reader && (Buffer.from(destination.viewingPublicKey.toBytes()).equals(oldDestination.viewingPublicKey.toBytes()) ||
                  Buffer.from(destination.nullifierPublicKey).equals(oldDestination.nullifierPublicKey))) {
                throw new Error("replacement domain repeated an old recipient key");
              }
              return reader ?? next;
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
