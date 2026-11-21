import { describe, expect, it } from "vitest";
import fixture from "./fixtures/aws-nitro-devnet.json";
import { verifyAwsNitroAttestation } from "../../src/attestation/aws-nitro.js";
import { verifyNativeNitroEvidence } from "../../src/attestation/boot-proof.js";
import { decodeAwsNitroAttestationCbor, decodeCbor } from "../../src/attestation/cbor.js";
import { requireHex } from "../../src/protocol/hex.js";

const evidence = requireHex(fixture.evidence);
const nonce = requireHex(fixture.nonce);
const binding = requireHex(fixture.binding);
const now = BigInt(fixture.now);
const { pcrs } = fixture;

describe("native Nitro evidence from a disposable AWS enclave", () => {
  it("verifies the real AWS root, certificate chain, signature and release and returns the replica key", async () => {
    await expect(verifyNativeNitroEvidence(evidence, nonce, binding, pcrs, now)).resolves.toBe(fixture.proofKey);
  });

  it.each([0, 1, 2, 3])("refuses a mismatch in pinned PCR %s", async (index) => {
    await expect(verifyNativeNitroEvidence(evidence, nonce, binding, {
      ...pcrs, [index]: "66".repeat(48),
    }, now)).rejects.toThrow("BootProofUnverified");
  });

  it("rejects a replayed nonce, changed discovery and old or future evidence", async () => {
    await expect(verifyNativeNitroEvidence(evidence, new Uint8Array(32), binding, pcrs, now)).rejects.toThrow("BootProofUnverified");
    await expect(verifyNativeNitroEvidence(evidence, nonce, new Uint8Array(32), pcrs, now)).rejects.toThrow("BootProofUnverified");
    await expect(verifyNativeNitroEvidence(evidence, nonce, binding, pcrs, now + 70_000n)).rejects.toThrow("BootProofUnverified");
    await expect(verifyNativeNitroEvidence(evidence, nonce, binding, pcrs, now - 70_000n)).rejects.toThrow("BootProofUnverified");
  });

  it("rejects truncated evidence and a modified signature", async () => {
    await expect(verifyNativeNitroEvidence(evidence.subarray(0, 80), nonce, binding, pcrs, now)).rejects.toThrow("BootProofUnverified");
    const corrupt = evidence.slice();
    corrupt[corrupt.length - 1] = (corrupt.at(-1) ?? 0) ^ 1;
    await expect(verifyNativeNitroEvidence(corrupt, nonce, binding, pcrs, now)).rejects.toThrow("BootProofUnverified");
  });

  it("rejects unpinned or misordered CA bundles, expiry and a different COSE algorithm", async () => {
    const [protectedHeaders, , payload, signature] = decodeCbor(evidence) as Uint8Array[];
    const document = decodeAwsNitroAttestationCbor(payload!) as Map<string, Uint8Array | Uint8Array[]>;
    const leaf = document.get("certificate") as Uint8Array;
    const chain = document.get("cabundle") as Uint8Array[];
    const cose = { protectedHeaders: protectedHeaders!, payload: payload!, signature: signature! };
    await expect(verifyAwsNitroAttestation(cose, leaf, [leaf, ...chain.slice(1)], Number(now))).rejects.toThrow("Untrusted AWS Nitro root");
    await expect(verifyAwsNitroAttestation(cose, leaf, [chain[0]!, ...chain.slice(1).reverse()], Number(now))).rejects.toThrow("certificate chain");
    await expect(verifyAwsNitroAttestation(cose, leaf, chain, Number(now + 86_400_000n))).rejects.toThrow("certificate chain");
    await expect(verifyAwsNitroAttestation({
      ...cose, protectedHeaders: new Uint8Array([0xa1, 0x01, 0x26]),
    }, leaf, chain, Number(now))).rejects.toThrow("COSE headers");
  });
});
