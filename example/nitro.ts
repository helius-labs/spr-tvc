import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import { setTimeout } from "node:timers/promises";
import type { Address } from "@solana/kit";
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
      minimumCustodyEpoch TEXT NOT NULL
    ) STRICT;`);
  const read = db.prepare("SELECT sequence, digest, minimumCustodyEpoch FROM checkpoints WHERE scope = ?");
  const save = db.prepare(`INSERT INTO checkpoints VALUES (?, ?, ?, ?)
    ON CONFLICT(scope) DO UPDATE SET sequence = excluded.sequence, digest = excluded.digest,
      minimumCustodyEpoch = excluded.minimumCustodyEpoch`);
  const current = () => read.get(scope) as NitroPolicyCheckpoint | undefined;
  const store: NitroPolicyStore = {
    async current() { return current(); },
    async accept(next) {
      db.exec("BEGIN IMMEDIATE");
      try {
        const previous = current();
        const accepted = advancesNitroPolicy(previous, next);
        if (accepted && previous?.sequence !== next.sequence) save.run(scope, next.sequence, next.digest, next.minimumCustodyEpoch);
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
    accepted.minimumCustodyEpoch === checkpoint.minimumCustodyEpoch;
}

export function requireOriginalPolicy(
  published: Awaited<ReturnType<typeof readPublishedNitroPolicy>>,
  accepted: NitroPolicyCheckpoint | undefined,
  replacement: bigint,
): void {
  const { policy } = published;
  const epoch = policy.targets[0]?.custodyEpoch;
  if (!acceptedPolicy(published, accepted) || policy.action !== "activate" || epoch === undefined ||
      BigInt(epoch) >= replacement || policy.targets.some(target => target.custodyEpoch !== epoch)) {
    throw new Error("start with both buckets serving the accepted policy for the original custody epoch only");
  }
}

export async function nativeDevnet(walletTrust: string, checkpoint: string, replacementEpoch: string) {
  const trust = JSON.parse(await readFile(walletTrust, "utf8")) as NitroTrust;
  if (trust.network !== "devnet") throw new Error("the Nitro rehearsal requires devnet wallet trust");
  if (!/^[1-9][0-9]{0,19}$/.test(replacementEpoch) || BigInt(replacementEpoch) > 2n ** 64n - 1n) {
    throw new Error("set NITRO_REPLACEMENT_EPOCH to a custody epoch");
  }
  const { store, close } = checkpointStore(checkpoint, trust);
  try {
    const service = createNitroDecryptionService({ trust, policyStore: store });
    return {
      service,
      close,
      async beforeSend() {
        const published = await readPublishedNitroPolicy(trust, AbortSignal.timeout(5_000));
        requireOriginalPolicy(published, await store.current(), BigInt(replacementEpoch));
      },
      async afterTransfer(recipient: Address) {
        const replacementTrust = { ...trust, minimumCustodyEpoch: replacementEpoch };
        const next = createNitroDecryptionService({ trust: replacementTrust, policyStore: store });
        const signal = AbortSignal.timeout(5 * 60_000);
        while (!signal.aborted) {
          try {
            await next.address(recipient, { signal, timeoutMs: 10_000 });
            const published = await readPublishedNitroPolicy(replacementTrust, signal);
            if (published.policy.action === "activate" && acceptedPolicy(published, await store.current())) return next;
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
