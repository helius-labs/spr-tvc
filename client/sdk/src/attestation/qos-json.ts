import { sha256 } from "@noble/hashes/sha256";
import { DecryptionServiceError } from "../wire/error.js";

const te = new TextEncoder();

/**
 * QOS canonical JSON. Integer numbers become decimal strings, null object
 * fields are omitted, and object keys sort by UTF-16 code units.
 */
export function canonicalizeQosJson(value: unknown): string {
  return qosJson(value);
}

export function qosJsonHash(value: unknown): Uint8Array {
  return sha256(te.encode(canonicalizeQosJson(value)));
}

function qosJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new DecryptionServiceError("BootProofUnverified");
    return JSON.stringify(String(value));
  }
  if (typeof value === "string") {
    if (/[\uD800-\uDFFF]/u.test(value)) throw new DecryptionServiceError("BootProofUnverified");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(qosJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record)
      .filter((key) => record[key] !== null && record[key] !== undefined)
      .sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${qosJson(record[key])}`).join(",")}}`;
  }
  throw new DecryptionServiceError("BootProofUnverified");
}
