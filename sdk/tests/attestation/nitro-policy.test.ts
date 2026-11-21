import { p256 } from "@noble/curves/p256";
import { describe, expect, it } from "vitest";
import {
  advancesNitroPolicy, nitroPolicySigningDigest, validateNitroTrust, verifyNitroPolicy,
  type NitroPolicy, type NitroTrust,
} from "../../src/attestation/nitro-policy.js";
import { signP256Prehash } from "../../src/crypto/p256.js";
import { encodeLowerHex } from "../../src/protocol/hex.js";

const privateKeys = [1, 2, 3, 4].map(byte => new Uint8Array(32).fill(byte));
const keys = privateKeys.map(key => encodeLowerHex(p256.getPublicKey(key, false)));
const now = 1_750_000_000_000n;
const trust: NitroTrust = {
  network: "mainnet",
  securityDomainId: "11".repeat(32),
  noteSeedCommitment: "22".repeat(32),
  threshold: 2,
  keys: keys.slice(0, 3),
  minimumSequence: "9",
  minimumCustodyEpoch: "1",
};
const binding: NitroPolicy = {
  version: 1,
  network: trust.network,
  securityDomainId: trust.securityDomainId,
  noteSeedCommitment: trust.noteSeedCommitment,
  sequence: "9",
  minimumCustodyEpoch: "1",
  validFromMs: String(now - 1n),
  expiresAtMs: String(now + 100n),
  targets: [{
    endpoint: "https://slot-a.example.com/",
    releaseId: "generation-9",
    custodyEpoch: "1",
    executableSha256: "33".repeat(32),
    pcrs: { 0: "11".repeat(48), 1: "22".repeat(48), 2: "33".repeat(48), 3: "44".repeat(48) },
  }],
};

function signatures(policy: NitroPolicy, ...signers: number[]) {
  return signers.map(index => ({
    key: keys[index]!,
    signature: encodeLowerHex(signP256Prehash(privateKeys[index]!, nitroPolicySigningDigest(policy))),
  }));
}
function manifest(policy: NitroPolicy, ...signers: number[]) {
  return JSON.stringify({ policy, signatures: signatures(policy, ...signers) });
}

describe("native Nitro release policy", () => {
  it("authorizes two distinct trusted P-256 signatures over a canonical policy", () => {
    validateNitroTrust(trust);
    const verified = verifyNitroPolicy(manifest(binding, 0, 2), trust, now);
    expect(verified.policy).toEqual(binding);
    expect(verified.checkpoint).toEqual({
      sequence: "9", minimumCustodyEpoch: "1", digest: encodeLowerHex(nitroPolicySigningDigest(binding)),
    });
    expect(verifyNitroPolicy(manifest(binding, 2, 0), trust, now).checkpoint).toEqual(verified.checkpoint);
  });

  it("rejects too few, duplicate, untrusted, invalid or stale signatures", () => {
    for (const invalid of [manifest(binding, 0), manifest(binding, 0, 0), manifest(binding, 0, 3)]) {
      expect(() => verifyNitroPolicy(invalid, trust, now)).toThrow();
    }
    const oldSignatures = signatures(binding, 0, 2);
    expect(() => verifyNitroPolicy(JSON.stringify({
      policy: { ...binding, targets: [{ ...binding.targets[0], endpoint: "https://new.example.com/" }] },
      signatures: oldSignatures,
    }), trust, now)).toThrow("InvalidSignature");
    expect(() => validateNitroTrust({ ...trust, keys: [keys[0]!, keys[0]!] })).toThrow();
    expect(() => validateNitroTrust({ ...trust, threshold: 1 })).toThrow();
    expect(() => validateNitroTrust({ ...trust, keys: ["00", keys[1]!] })).toThrow();
  });

  it("rejects a conflicting trust domain, seed, network or version, even with valid signatures", () => {
    for (const policy of [
      { ...binding, securityDomainId: "44".repeat(32) },
      { ...binding, noteSeedCommitment: "44".repeat(32) },
      { ...binding, network: "devnet" },
      { ...binding, sequence: "8" },
      { ...binding, sequence: "09" },
      { ...binding, version: 2 },
    ] as const) expect(() => verifyNitroPolicy(manifest(policy as NitroPolicy, 0, 1), trust, now)).toThrow();
  });

  it("checks the inclusive start, exclusive expiration and maximum policy lifetime", () => {
    const signed = manifest(binding, 0, 1);
    expect(() => verifyNitroPolicy(signed, trust, now - 2n)).toThrow();
    expect(() => verifyNitroPolicy(signed, trust, now - 1n)).not.toThrow();
    expect(() => verifyNitroPolicy(signed, trust, now + 100n)).toThrow();
    expect(() => verifyNitroPolicy(manifest({
      ...binding, expiresAtMs: String(now + 7n * 86_400_000n),
    }, 0, 1), trust, now)).toThrow();
  });

  it("rejects unmeasured, ambiguous or insecure routes", () => {
    const first = binding.targets[0]!;
    for (const targets of [
      [],
      [first, first],
      Array.from({ length: 9 }, (_, i) => ({ ...first, endpoint: `https://slot-${i}.example.com/` })),
      [{ ...first, endpoint: "http://127.0.0.1/" }],
      [{ ...first, endpoint: "https://name:pw@example.com/" }],
      [{ ...first, endpoint: "https://example.com/?a=1" }],
      [{ ...first, endpoint: "https://example.com" }],
      [{ ...first, releaseId: "../escape" }],
      [{ ...first, pcrs: { ...first.pcrs, 0: "00".repeat(48) } }],
      [{ ...first, pcrs: { ...first.pcrs, 3: "33".repeat(32) } }],
      [{ ...first, pcrs: { ...first.pcrs, 8: "33".repeat(48) } }],
      [{ ...first, executableSha256: "00".repeat(32) }],
    ]) expect(() => verifyNitroPolicy(manifest({ ...binding, targets }, 0, 1), trust, now)).toThrow();
    expect(() => verifyNitroPolicy(manifest({
      ...binding, network: "devnet", targets: [{ ...first, endpoint: "http://127.0.0.1/" }],
    }, 0, 1), { ...trust, network: "devnet" }, now)).not.toThrow();
  });

  it("rejects duplicate JSON fields before applying a valid signature", () => {
    expect(() => verifyNitroPolicy(
      manifest(binding, 0, 1).replace('"sequence":"9"', '"sequence":"1","sequence":"9"'),
      trust, now,
    )).toThrow("DuplicateJsonField");
  });

  it("requires every signed target to meet the policy custody floor", () => {
    const oldTarget = binding.targets[0]!;
    const next: NitroPolicy = {
      ...binding, sequence: "10", minimumCustodyEpoch: "2",
      targets: [{ ...oldTarget, custodyEpoch: "2" }],
    };
    const retired = verifyNitroPolicy(manifest(next, 0, 1), trust, now).checkpoint;
    const old = verifyNitroPolicy(manifest({ ...binding, sequence: "11" }, 0, 1), trust, now).checkpoint;
    expect(advancesNitroPolicy(retired, old)).toBe(false);
    expect(() => verifyNitroPolicy(manifest({ ...next, targets: [oldTarget] }, 0, 1), trust, now)).toThrow();
    expect(() => verifyNitroPolicy(manifest(binding, 0, 1), { ...trust, minimumCustodyEpoch: "2" }, now)).toThrow();
    expect(() => verifyNitroPolicy(manifest({ ...next, minimumCustodyEpoch: "02" }, 0, 1), trust, now)).toThrow();
  });

  it("accepts identical checkpoints and forward sequences, refusing rollback and equivocation", () => {
    const first = verifyNitroPolicy(manifest(binding, 0, 1), trust, now).checkpoint;
    expect(advancesNitroPolicy(undefined, first)).toBe(true);
    expect(advancesNitroPolicy(first, first)).toBe(true);
    expect(advancesNitroPolicy(first, { ...first, sequence: "10", digest: "ab" })).toBe(true);
    expect(advancesNitroPolicy(first, { ...first, sequence: "8", digest: first.digest })).toBe(false);
    expect(advancesNitroPolicy(first, { ...first, sequence: "9", digest: "ab" })).toBe(false);
  });
});
