import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { describe, expect, it } from "vitest";
import { qosDecrypt, qosEncrypt, qosEncryptWith, parseQosP256Public } from "../../src/crypto/qos.js";
import { encodeLowerHex } from "../../src/protocol/hex.js";

const secret = (label: string) => sha256(new TextEncoder().encode(label));
const RECEIVER = secret("qos-receiver");
const RECEIVER_PUBLIC = p256.getPublicKey(RECEIVER, false);

describe("QOS envelope", () => {
  it("round-trips an envelope stored at a buffer offset", async () => {
    const plaintext = new TextEncoder().encode("wallet operation");
    const envelope = await qosEncrypt(RECEIVER_PUBLIC, plaintext);
    const backing = new Uint8Array(envelope.length + 2);
    backing.set(envelope, 1);
    expect(qosDecrypt(RECEIVER, backing.subarray(1, -1))).toEqual(plaintext);
  });

  it("rejects a nonce that is not exactly the AES-GCM length", () => {
    // Without this the envelope encoder would write a long nonce straight over
    // the ephemeral public key that follows it.
    for (const length of [0, 11, 13, 32]) {
      expect(() =>
        qosEncryptWith(RECEIVER_PUBLIC, new Uint8Array([1]), secret("eph"), new Uint8Array(length)),
      ).toThrowError("InvalidEncryptedEnvelope");
    }
  });

  it("rejects a truncated envelope, including one held inside a larger buffer", () => {
    const backing = new Uint8Array(256).fill(0xff);
    for (const length of [0, 12, 76, 80]) {
      const truncated = backing.subarray(0, length);
      expect(() => qosDecrypt(RECEIVER, truncated)).toThrowError("InvalidEncryptedEnvelope");
    }
  });

  it("rejects a declared message length that disagrees with the envelope", async () => {
    const envelope = await qosEncrypt(RECEIVER_PUBLIC, new Uint8Array([1, 2, 3]));
    const shortened = envelope.slice(0, envelope.length - 1);
    expect(() => qosDecrypt(RECEIVER, shortened)).toThrowError("InvalidEncryptedEnvelope");
    const extended = new Uint8Array(envelope.length + 1);
    extended.set(envelope);
    expect(() => qosDecrypt(RECEIVER, extended)).toThrowError("InvalidEncryptedEnvelope");
  });

  it("rejects the wrong receiver and a corrupted tag", async () => {
    const envelope = await qosEncrypt(RECEIVER_PUBLIC, new Uint8Array([1, 2, 3]));
    expect(() => qosDecrypt(secret("other-receiver"), envelope)).toThrowError(
      "InvalidEncryptedEnvelope",
    );
    const tampered = envelope.slice();
    tampered.set([(tampered.at(-1) ?? 0) ^ 1], tampered.length - 1);
    expect(() => qosDecrypt(RECEIVER, tampered)).toThrowError("InvalidEncryptedEnvelope");
  });

  it("splits the 130-byte QOS public key into distinct encryption and signing keys", () => {
    const encryption = p256.getPublicKey(secret("enc"), false);
    const signing = p256.getPublicKey(secret("sig"), false);
    const parsed = parseQosP256Public(Uint8Array.from([...encryption, ...signing]));
    expect(encodeLowerHex(parsed.encryption)).toBe(encodeLowerHex(encryption));
    expect(encodeLowerHex(parsed.signing)).toBe(encodeLowerHex(signing));
    expect(() => parseQosP256Public(encryption)).toThrowError("InvalidPublicKey");
  });
});
