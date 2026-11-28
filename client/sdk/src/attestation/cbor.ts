// Strict CBOR for AWS Nitro COSE_Sign1 attestation documents.
//
// This is deliberately not a general CBOR implementation. It accepts only the
// narrow subset that NSM emits, because the bytes are attacker-controlled and
// are parsed *before* any signature is verified:
//
//   - definite lengths by default; a dedicated Nitro entry point accepts only
//     the bounded indefinite root map emitted by real attestation documents;
//   - shortest-form argument encoding only, so a document has one encoding;
//   - no floats, no simple values beyond false/true/null;
//   - byte strings are copied, never returned as views into the input buffer;
//   - maps become `Map`, so a `"__proto__"` key cannot reach a prototype setter;
//   - duplicate map keys are rejected;
//   - nesting is depth-limited and trailing bytes are rejected.

import { MAX_SAFE_INTEGER_BIGINT } from "../wire/constants.js";

const MAJOR_SHIFT = 5;
const ADDITIONAL_MASK = 0x1f;
const BITS_PER_BYTE = 8n;

const MAJOR_UNSIGNED = 0;
const MAJOR_NEGATIVE = 1;
const MAJOR_BYTES = 2;
const MAJOR_TEXT = 3;
const MAJOR_ARRAY = 4;
const MAJOR_MAP = 5;
const MAJOR_TAG = 6;
const MAJOR_SIMPLE = 7;

const INLINE_ARG_LIMIT = 24;
const ADDITIONAL_U8 = 24;
const ADDITIONAL_U16 = 25;
const ADDITIONAL_U32 = 26;
const ADDITIONAL_U64 = 27;
const ADDITIONAL_INDEFINITE = 31;

const U16_BYTES = 2;
const U32_BYTES = 4;
const U64_BYTES = 8;
const U16_MIN = 0x100n;
const U32_MIN = 0x1_0000n;
const U64_MIN = 0x1_0000_0000n;

const SIMPLE_FALSE = 20;
const SIMPLE_TRUE = 21;
const SIMPLE_NULL = 22;
const CBOR_BREAK = 0xff;

const COSE_SIGN1_TAG = 18;
const MAX_DEPTH = 16;
const MAX_INDEFINITE_ROOT_MAP_ENTRIES = 32;

const td = new TextDecoder("utf-8", { fatal: true });

export type CborValue =
  | null
  | boolean
  | number
  | Uint8Array
  | string
  | CborValue[]
  | Map<string | number, CborValue>;

export class CborError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CborError";
  }
}

class Reader {
  #bytes: Uint8Array;
  #allowIndefiniteRootMap: boolean;
  #offset = 0;

  constructor(bytes: Uint8Array, allowIndefiniteRootMap = false) {
    this.#bytes = bytes;
    this.#allowIndefiniteRootMap = allowIndefiniteRootMap;
  }

  get exhausted(): boolean {
    return this.#offset === this.#bytes.length;
  }

  #take(length: number): Uint8Array {
    if (length < 0 || this.#bytes.length - this.#offset < length) {
      throw new CborError("truncated CBOR item");
    }
    const start = this.#offset;
    this.#offset += length;
    return this.#bytes.slice(start, this.#offset);
  }

  #byte(): number {
    const value = this.#bytes[this.#offset];
    if (value === undefined) throw new CborError("truncated CBOR item");
    this.#offset += 1;
    return value;
  }

  #nextIsBreak(): boolean {
    return this.#bytes[this.#offset] === CBOR_BREAK;
  }

  #indefiniteRootMap(depth: number): Map<string | number, CborValue> {
    const entries = new Map<string | number, CborValue>();
    while (!this.#nextIsBreak()) {
      if (entries.size >= MAX_INDEFINITE_ROOT_MAP_ENTRIES) {
        throw new CborError("indefinite root map has too many entries");
      }
      const key = this.read(depth + 1);
      if (typeof key !== "string" && typeof key !== "number") {
        throw new CborError("unsupported CBOR map key");
      }
      if (this.#nextIsBreak()) throw new CborError("indefinite root map is missing a value");
      if (entries.has(key)) throw new CborError("duplicate CBOR map key");
      entries.set(key, this.read(depth + 1));
    }
    this.#byte();
    return entries;
  }

  /** Reads the argument, rejecting any non-shortest encoding of it. */
  #argument(additional: number): number {
    if (additional < INLINE_ARG_LIMIT) return additional;
    if (additional === ADDITIONAL_U8) {
      const value = this.#byte();
      if (value < INLINE_ARG_LIMIT) throw new CborError("non-minimal CBOR argument");
      return value;
    }
    if (additional === ADDITIONAL_U16 || additional === ADDITIONAL_U32 || additional === ADDITIONAL_U64) {
      const width = additional === ADDITIONAL_U16 ? U16_BYTES : additional === ADDITIONAL_U32 ? U32_BYTES : U64_BYTES;
      const minimum = additional === ADDITIONAL_U16 ? U16_MIN : additional === ADDITIONAL_U32 ? U32_MIN : U64_MIN;
      const bytes = this.#take(width);
      let value = 0n;
      for (const byte of bytes) value = (value << BITS_PER_BYTE) | BigInt(byte);
      if (value < minimum) throw new CborError("non-minimal CBOR argument");
      if (value > MAX_SAFE_INTEGER_BIGINT) throw new CborError("CBOR argument too large");
      return Number(value);
    }
    // 28-30 are reserved; 31 is the indefinite-length marker.
    throw new CborError("unsupported CBOR argument encoding");
  }

  read(depth: number): CborValue {
    if (depth > MAX_DEPTH) throw new CborError("CBOR nesting too deep");
    const initial = this.#byte();
    const major = initial >> MAJOR_SHIFT;
    const additional = initial & ADDITIONAL_MASK;

    if (major === MAJOR_SIMPLE) {
      if (additional === SIMPLE_FALSE) return false;
      if (additional === SIMPLE_TRUE) return true;
      if (additional === SIMPLE_NULL) return null;
      throw new CborError("unsupported CBOR simple value");
    }

    if (
      additional === ADDITIONAL_INDEFINITE &&
      major === MAJOR_MAP &&
      depth === 0 &&
      this.#allowIndefiniteRootMap
    ) {
      return this.#indefiniteRootMap(depth);
    }

    const argument = this.#argument(additional);
    switch (major) {
      case MAJOR_UNSIGNED:
        return argument;
      case MAJOR_NEGATIVE:
        return -1 - argument;
      case MAJOR_BYTES:
        return this.#take(argument);
      case MAJOR_TEXT:
        return td.decode(this.#take(argument));
      case MAJOR_ARRAY: {
        const items: CborValue[] = [];
        for (let index = 0; index < argument; index += 1) items.push(this.read(depth + 1));
        return items;
      }
      case MAJOR_MAP: {
        const entries = new Map<string | number, CborValue>();
        for (let index = 0; index < argument; index += 1) {
          const key = this.read(depth + 1);
          if (typeof key !== "string" && typeof key !== "number") {
            throw new CborError("unsupported CBOR map key");
          }
          if (entries.has(key)) throw new CborError("duplicate CBOR map key");
          entries.set(key, this.read(depth + 1));
        }
        return entries;
      }
      case MAJOR_TAG: {
        // Only the COSE_Sign1 wrapper, and only as the outermost item: NSM
        // emits no tags inside the attestation payload, so accepting one at
        // depth would widen the grammar for no reason.
        if (argument !== COSE_SIGN1_TAG || depth !== 0) {
          throw new CborError("unsupported CBOR tag");
        }
        return this.read(depth + 1);
      }
      default:
        throw new CborError("unsupported CBOR major type");
    }
  }
}

/** Decodes one deterministic CBOR item and rejects trailing bytes. */
export function decodeCbor(bytes: Uint8Array): CborValue {
  const reader = new Reader(bytes);
  const value = reader.read(0);
  if (!reader.exhausted) throw new CborError("trailing bytes after CBOR item");
  return value;
}

/** Decodes the one non-deterministic container NSM emits around an attestation. */
export function decodeAwsNitroAttestationCbor(bytes: Uint8Array): CborValue {
  const reader = new Reader(bytes, true);
  const value = reader.read(0);
  if (!reader.exhausted) throw new CborError("trailing bytes after CBOR item");
  return value;
}
