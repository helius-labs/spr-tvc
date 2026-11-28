import { MAX_U64_BIGINT } from "./constants.js";
import { DecryptionServiceError } from "./error.js";

export function encodeDecimalU64(value: bigint): string {
  if (value < 0n || value > MAX_U64_BIGINT) {
    throw new DecryptionServiceError("InvalidDecimal");
  }
  return value.toString(10);
}

export function decodeDecimalU64(input: string): bigint {
  let value: bigint;
  try {
    value = BigInt(input);
  } catch {
    throw new DecryptionServiceError("InvalidDecimal");
  }
  if (value < 0n || value > MAX_U64_BIGINT || value.toString(10) !== input) {
    throw new DecryptionServiceError("InvalidDecimal");
  }
  return value;
}
