import { DecryptionServiceError } from "./error.js";

function jsonString(value: string): string {
  // A Unicode-aware match catches lone surrogates but accepts valid pairs.
  if (/[\uD800-\uDFFF]/u.test(value)) {
    throw new DecryptionServiceError("InvalidCanonicalJson");
  }
  return JSON.stringify(value);
}

export function canonicalizeJsonValue(value: unknown): string {
  if (typeof value === "string") return jsonString(value);
  if (value === null || typeof value === "boolean" || Number.isInteger(value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${Array.from(value, canonicalizeJsonValue).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const entries = Object.keys(record).sort().map(
      (key) => `${jsonString(key)}:${canonicalizeJsonValue(record[key])}`,
    );
    return `{${entries.join(",")}}`;
  }
  throw new DecryptionServiceError("InvalidCanonicalJson");
}

export function isRfc8785(input: string): boolean {
  try {
    return canonicalizeJsonValue(JSON.parse(input) as unknown) === input;
  } catch {
    return false;
  }
}
