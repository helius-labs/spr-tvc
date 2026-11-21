import { sha256 } from "@noble/hashes/sha256";
import { beforeEach, expect, it, vi } from "vitest";
import { verifyNitroCustodyEvidence } from "../../src/attestation/boot-proof.js";
import {
  verifyCustodyReceipt, type CustodyExpectation, type CustodyReceipt,
} from "../../src/attestation/nitro-custody.js";
import { encodeLowerHex, requireHex } from "../../src/protocol/hex.js";
import { canonicalizeJsonValue } from "../../src/protocol/jcs.js";

vi.mock("../../src/attestation/boot-proof.js", () => ({
  verifyNitroCustodyEvidence: vi.fn(),
}));

const expectation: CustodyExpectation = {
  network: "mainnet",
  securityDomainId: "aa".repeat(32),
  releaseId: "rotation-a",
  epoch: "2",
  noteSeedCommitment: "bb".repeat(32),
  recipientPublicKeys: Array.from({ length: 6 }, (_, i) => `a${i}`.repeat(64)),
  pcrs: { 0: "11".repeat(48), 1: "22".repeat(48), 2: "33".repeat(48), 3: "44".repeat(48) },
};
const nonce = new Uint8Array(32).fill(5);
const now = 1_750_000_000_000n;

function receipt(): CustodyReceipt {
  return {
    network: "mainnet", releaseId: expectation.releaseId, securityDomainId: expectation.securityDomainId,
    custody: {
      epoch: "2", noteSeedCommitment: expectation.noteSeedCommitment!,
      shareCommitments: Array.from({ length: 6 }, (_, i) => `b${i}`.repeat(32)),
    },
    packages: expectation.recipientPublicKeys.map(key => ({
      recipientSha256: encodeLowerHex(sha256(requireHex(key))),
      ciphertext: "ff".repeat(256),
    })),
  };
}

const verify = (result: CustodyReceipt, expected = expectation) =>
  verifyCustodyReceipt(JSON.stringify({ result, evidence: "abcd" }), expected, nonce, now);

beforeEach(() => {
  vi.resetAllMocks();
});

it("binds the entire ordered rotation receipt to a fresh challenge and independent PCRs", async () => {
  const result = receipt();
  const binding = sha256(new TextEncoder().encode(
    "SPR/native-nitro/custody/v1" + canonicalizeJsonValue(result),
  ));
  await expect(verify(result)).resolves.toEqual(result);
  expect(verifyNitroCustodyEvidence).toHaveBeenCalledWith(
    requireHex("abcd"), nonce, binding, expectation.pcrs, now,
  );
});

it("rejects substituted recipients, commitments, seed, epoch or network before accepting a receipt", async () => {
  const result = receipt();
  for (const manipulated of [
    { ...result, network: "devnet" as const },
    { ...result, releaseId: "another-release" },
    { ...result, securityDomainId: "cc".repeat(32) },
    { ...result, custody: { ...result.custody, epoch: "1" } },
    { ...result, custody: { ...result.custody, noteSeedCommitment: "ff".repeat(32) } },
    { ...result, custody: { ...result.custody, shareCommitments: Array(6).fill("aa".repeat(32)) } },
    { ...result, packages: result.packages.slice(1) },
    { ...result, packages: [...result.packages].reverse() },
    { ...result, packages: [{ ...result.packages[0]!, ciphertext: "00" }, ...result.packages.slice(1)] },
  ]) await expect(verify(manipulated)).rejects.toThrow();
  await expect(verify(result, { ...expectation, noteSeedCommitment: undefined })).rejects.toThrow();
  expect(verifyNitroCustodyEvidence).not.toHaveBeenCalled();
});

it("requires genuine evidence even when all receipt fields match", async () => {
  vi.mocked(verifyNitroCustodyEvidence).mockRejectedValueOnce(new Error("untrusted evidence"));
  await expect(verify(receipt())).rejects.toThrow("untrusted evidence");
});
