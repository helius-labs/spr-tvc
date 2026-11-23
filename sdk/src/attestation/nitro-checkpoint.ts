import { DecryptionServiceError } from "../protocol/error.js";
import {
  advancesNitroPolicy, isValidNitroPolicyCheckpoint, sameNitroCheckpoint, type NitroPolicyCheckpoint, type NitroPolicyStore, type NitroTrust,
} from "./nitro-policy.js";

const DATABASE = "spr-nitro-policy";
const CHECKPOINTS = "checkpoints";

function storageError() {
  return new DecryptionServiceError("ReleasePolicyInvalid", "checkpoint storage unavailable");
}

function storedCheckpoint(record: IDBCursorWithValue | null): NitroPolicyCheckpoint | undefined {
  if (record === null) return undefined;
  const value: unknown = record.value;
  if (!isValidNitroPolicyCheckpoint(value)) throw storageError();
  return value;
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
        const request = records.openCursor(key);
        let result: T;
        request.onsuccess = () => {
          try {
            result = run(storedCheckpoint(request.result), records);
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
    async accept(update) {
      const next = update[0].checkpoint;
      if (!isValidNitroPolicyCheckpoint(next)) throw storageError();
      return transact("readwrite", (current, records) => {
        if (!advancesNitroPolicy(current, update)) return false;
        if (!sameNitroCheckpoint(current, next)) records.put(next, key);
        return true;
      });
    },
  };
}
