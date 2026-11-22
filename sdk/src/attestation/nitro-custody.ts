import { sha256 } from "@noble/hashes/sha256";
import { verifyNitroCustodyEvidence } from "./boot-proof.js";
import type { NitroPcrs, NitroTargetPcrs } from "./nitro-policy.js";
import { decodeDecimalU64 } from "../protocol/decimal.js";
import { DecryptionServiceError } from "../protocol/error.js";
import { encodeLowerHex, requireHex } from "../protocol/hex.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import { assertExactObjectKeys, parseStrictJson } from "../protocol/json.js";
import type { Network } from "../protocol/types.js";

export type CustodyReceipt = {
  network: Network;
  securityDomainId: string;
  releaseId: string;
  custody: { epoch: string; noteSeedCommitment: string; shareCommitments: string[] };
  packages: { recipientSha256: string; ciphertext: string }[];
};

export type CustodyExpectation = {
  network: Network;
  securityDomainId: string;
  releaseId: string;
  epoch: string;
  /** For rotation, the independently recorded commitment of the original seed. */
  noteSeedCommitment?: string;
  recipientPublicKeys: string[];
  pcrs: NitroPcrs | NitroTargetPcrs;
};

const te = new TextEncoder();

export async function verifyCustodyReceipt(
  text: string, expected: CustodyExpectation, nonce: Uint8Array, now: bigint,
): Promise<CustodyReceipt> {
  const { result, evidence } = parseStrictJson<{ result: CustodyReceipt; evidence: string }>(
    text, ["result", "evidence"],
  );
  assertExactObjectKeys(result, ["network", "securityDomainId", "releaseId", "custody", "packages"], "BootProofUnverified");
  assertExactObjectKeys(result.custody, ["epoch", "noteSeedCommitment", "shareCommitments"], "BootProofUnverified");
  const { custody, packages } = result;
  const epoch = decodeDecimalU64(custody.epoch);
  const seedMatches = expected.noteSeedCommitment === undefined
    ? epoch === 1n
    : expected.noteSeedCommitment === custody.noteSeedCommitment;
  if (!seedMatches || result.network !== expected.network || result.securityDomainId !== expected.securityDomainId ||
      result.releaseId !== expected.releaseId || custody.epoch !== expected.epoch ||
      epoch < 1n || (epoch > 1n) !== (4 in expected.pcrs) || nonce.length !== 32 ||
      !requireHex(custody.noteSeedCommitment, 32).some(byte => byte !== 0) ||
      !Array.isArray(custody.shareCommitments) || custody.shareCommitments.length !== 6 ||
      new Set(custody.shareCommitments).size !== 6 || !Array.isArray(packages) || packages.length !== 6 ||
      expected.recipientPublicKeys.length !== 6 || typeof evidence !== "string" || evidence.length > 32_768) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  const recipients = new Set<string>();
  for (const [index, item] of packages.entries()) {
    assertExactObjectKeys(item, ["recipientSha256", "ciphertext"], "BootProofUnverified");
    const spki = requireHex(expected.recipientPublicKeys[index]!);
    const fingerprint = encodeLowerHex(sha256(spki));
    if (item.recipientSha256 !== fingerprint || recipients.has(fingerprint) ||
        ![256, 384, 512].includes(requireHex(item.ciphertext).length) ||
        !requireHex(custody.shareCommitments[index]!, 32).some(byte => byte !== 0)) {
      throw new DecryptionServiceError("BootProofUnverified");
    }
    recipients.add(fingerprint);
  }

  const binding = sha256(te.encode("SPR/native-nitro/custody/v1" + canonicalizeJsonValue(result)));
  await verifyNitroCustodyEvidence(requireHex(evidence), nonce, binding, expected.pcrs, now);
  return result;
}
