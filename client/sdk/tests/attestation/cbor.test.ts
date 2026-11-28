// Covers INV-14 (strict deterministic CBOR subset safety before signature verification, driven by
// shared Rust/TypeScript conformance vectors).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  CborError,
  decodeAwsNitroAttestationCbor,
  decodeCbor,
} from "../../src/attestation/cbor.js";
import { decodeLowerHex, encodeLowerHex } from "../../src/wire/hex.js";

type AcceptVector = { name: string; hex: string; kind: string; value: unknown };
type RejectVector = { name: string; hex: string; ts_error: string };
type CborVectors = {
  accept: AcceptVector[];
  reject: RejectVector[];
  nitro_root: {
    accept_hex: string;
    reject: RejectVector[];
  };
};

const SHARED_VECTORS_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../tests/fixtures/cbor-vectors.json",
);
const SHARED_VECTORS = JSON.parse(readFileSync(SHARED_VECTORS_PATH, "utf8")) as CborVectors;

function decodeHex(hex: string) {
  return decodeCbor(decodeLowerHex(hex));
}

describe("strict CBOR decoder", () => {
  it("decodes the deterministic subset an attestation document uses", () => {
    for (const vector of SHARED_VECTORS.accept) {
      const decoded = decodeHex(vector.hex);
      if (vector.kind === "bytes") {
        expect(encodeLowerHex(decoded as Uint8Array), vector.name).toBe(vector.value);
      } else {
        expect(decoded, vector.name).toEqual(vector.value);
      }
    }
  });

  it("decodes maps into a Map keyed by text or integer", () => {
    const value = decodeHex("a2616101010f") as Map<string | number, unknown>;
    expect(value).toBeInstanceOf(Map);
    expect(value.get("a")).toBe(1);
    expect(value.get(1)).toBe(15);
  });

  it("keeps a __proto__ key as inert data instead of reaching a prototype setter", () => {
    // a1 69 5f5f70726f746f5f5f a0  =>  {"__proto__": {}}
    const value = decodeHex("a1695f5f70726f746f5f5fa0") as Map<string, unknown>;
    expect(value.get("__proto__")).toBeInstanceOf(Map);
    expect(Object.getPrototypeOf(value)).toBe(Map.prototype);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("copies byte strings rather than viewing the input buffer", () => {
    const input = decodeLowerHex("43010203");
    const bytes = decodeCbor(input) as Uint8Array;
    input.fill(0xff);
    expect(encodeLowerHex(bytes)).toBe("010203");
  });

  it("rejects every shared negative vector (indefinite, non-minimal, floats, duplicates, truncation, depth, huge lengths, UTF-8)", () => {
    for (const vector of SHARED_VECTORS.reject) {
      const decode = () => decodeHex(vector.hex);
      if (vector.ts_error) {
        expect(decode, vector.name).toThrowError(CborError);
        expect(decode, vector.name).toThrowError(vector.ts_error);
      } else {
        expect(decode, vector.name).toThrow();
      }
    }
  });

  it("accepts only the bounded indefinite root map emitted by AWS Nitro", () => {
    const rootBytes = decodeLowerHex(SHARED_VECTORS.nitro_root.accept_hex);
    expect(() => decodeCbor(rootBytes)).toThrowError(CborError);
    const value = decodeAwsNitroAttestationCbor(rootBytes) as Map<string | number, unknown>;
    expect(value.get("module_id")).toBe("m");
    expect(value.get("pcrs")).toBeInstanceOf(Map);

    for (const vector of SHARED_VECTORS.nitro_root.reject) {
      expect(
        () => decodeAwsNitroAttestationCbor(decodeLowerHex(vector.hex)),
        vector.name,
      ).toThrowError(vector.ts_error);
    }
  });

  it("unwraps the COSE_Sign1 tag only as the outermost item", () => {
    expect(decodeHex("d24101")).toEqual(decodeLowerHex("01"));
    // 81 d2 4101 => [18(h'01')]; a tag nested inside the payload is rejected.
    expect(() => decodeHex("81d24101")).toThrowError(/unsupported CBOR tag/);
  });
});
