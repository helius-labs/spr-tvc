import { decodeDecimalU64 } from "../protocol/decimal.js";
import { DecryptionServiceError } from "../protocol/error.js";
import { requireHex } from "../protocol/hex.js";
import { advancesNitroPolicy, type NitroPolicyCheckpoint, type NitroPolicyStore, type NitroTrust } from "./nitro-policy.js";

const DATABASE = "spr-nitro-policy";
const CHECKPOINTS = "checkpoints";

function storageError() {
  return new DecryptionServiceError("ReleasePolicyInvalid", "checkpoint storage unavailable");
}

function validate(value: NitroPolicyCheckpoint): void {
  if (typeof value.recoveryOnly !== "boolean" || decodeDecimalU64(value.sequence) === 0n || decodeDecimalU64(value.minimumCustodyEpoch) === 0n ||
      !requireHex(value.digest, 32).some(byte => byte !== 0)) throw storageError();
}

/** The browser commits the compare-and-set across all tabs before accepting it. */
export function indexedDbNitroPolicyStore(trust: Pick<NitroTrust, "network" | "securityDomainId">): NitroPolicyStore {
  const factory = globalThis.indexedDB;
  if (!factory) throw storageError();
  const key = `${trust.network}/${trust.securityDomainId}`;

  async function transact<T>(
    mode: IDBTransactionMode,
    run: (current: NitroPolicyCheckpoint | undefined, records: IDBObjectStore) => T,
  ): Promise<T> {
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = factory.open(DATABASE, 1);
      request.onupgradeneeded = () => request.result.createObjectStore(CHECKPOINTS);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(storageError());
    });
    try {
      return await new Promise<T>((resolve, reject) => {
        const tx = db.transaction(CHECKPOINTS, mode, { durability: "strict" });
        const records = tx.objectStore(CHECKPOINTS);
        const request = records.get(key);
        let result: T;
        request.onsuccess = () => {
          try {
            const current = request.result as NitroPolicyCheckpoint | undefined;
            if (current !== undefined) validate(current);
            result = run(current, records);
          } catch {
            tx.abort();
          }
        };
        tx.oncomplete = () => resolve(result);
        tx.onabort = () => reject(storageError());
      });
    } finally {
      db.close();
    }
  }

  return {
    current: () => transact("readonly", current => current),
    async accept(next) {
      validate(next);
      return transact("readwrite", (current, records) => {
        if (!advancesNitroPolicy(current, next)) return false;
        if (current?.sequence !== next.sequence) records.put(next, key);
        return true;
      });
    },
  };
}
