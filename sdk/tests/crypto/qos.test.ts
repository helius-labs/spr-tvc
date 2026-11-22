import { p256 } from "@noble/curves/p256";
import * as hashes from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { describe, expect, it, vi } from "vitest";
import { qosDecrypt, qosEncrypt, qosEncryptWith, parseQosP256Public } from "../../src/crypto/qos.js";
import { encodeLowerHex } from "../../src/protocol/hex.js";

vi.mock("@noble/hashes/hmac", { spy: true });

const secret = (label: string) => sha256(new TextEncoder().encode(label));
const RECEIVER = secret("qos-receiver");
const RECEIVER_PUBLIC = p256.getPublicKey(RECEIVER, false);

describe("QOS envelope", () => {
  it("round-trips an envelope stored at a buffer offset", () => {
    const plaintext = new TextEncoder().encode("wallet operation");
    const envelope = qosEncrypt(RECEIVER_PUBLIC, plaintext);
    const backing = new Uint8Array(envelope.length + 2);
    backing.set(envelope, 1);
    expect(qosDecrypt(RECEIVER, backing.subarray(1, -1))).toEqual(plaintext);
  });

  it("wipes its ephemeral private key, shared points and HMAC buffers on success and failures", async () => {
    const ephemeral = secret("envelope-wipe");
    const rejectedEphemeral = secret("rejected-envelope-wipe");
    const receiverBefore = RECEIVER.slice();
    const scratch: Uint8Array[] = [];
    const getSharedSecret = p256.getSharedSecret;
    const { hmac } = await vi.importActual<typeof hashes>("@noble/hashes/hmac");
    const point = vi.spyOn(p256, "getSharedSecret").mockImplementation((...args) => {
      const shared = getSharedSecret(...args);
      scratch.push(shared);
      return shared;
    });
    const derive = vi.mocked(hashes.hmac).mockImplementation((hash, key, message) => {
      if (key instanceof Uint8Array) scratch.push(key);
      const material = hmac(hash, key, message);
      scratch.push(material);
      return material;
    });
    const generate = vi.spyOn(p256.utils, "randomPrivateKey").mockReturnValueOnce(ephemeral);
    try {
      const plaintext = Uint8Array.of(1);
      const envelope = qosEncrypt(RECEIVER_PUBLIC, plaintext);
      expect(qosDecrypt(RECEIVER, envelope)).toEqual(plaintext);
      envelope[envelope.length - 1] = envelope.at(-1)! ^ 1;
      expect(() => qosDecrypt(RECEIVER, envelope)).toThrowError("InvalidEncryptedEnvelope");
      generate.mockReturnValueOnce(rejectedEphemeral);
      expect(() => qosEncrypt(new Uint8Array(), plaintext)).toThrowError("InvalidPublicKey");
      expect(scratch).toHaveLength(9);
      for (const buffer of [ephemeral, rejectedEphemeral, ...scratch]) expect(buffer).toEqual(new Uint8Array(buffer.length));
      expect(RECEIVER).toEqual(receiverBefore);
    } finally {
      generate.mockRestore();
      derive.mockRestore();
      point.mockRestore();
    }
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

  it("rejects a declared message length that disagrees with the envelope", () => {
    const envelope = qosEncrypt(RECEIVER_PUBLIC, new Uint8Array([1, 2, 3]));
    const shortened = envelope.slice(0, envelope.length - 1);
    expect(() => qosDecrypt(RECEIVER, shortened)).toThrowError("InvalidEncryptedEnvelope");
    const extended = new Uint8Array(envelope.length + 1);
    extended.set(envelope);
    expect(() => qosDecrypt(RECEIVER, extended)).toThrowError("InvalidEncryptedEnvelope");
  });

  it("rejects the wrong receiver and a corrupted tag", () => {
    const envelope = qosEncrypt(RECEIVER_PUBLIC, new Uint8Array([1, 2, 3]));
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
