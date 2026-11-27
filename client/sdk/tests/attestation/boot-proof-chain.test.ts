// Runs against the real Turnkey/AWS Nitro seam, with nothing mocked. A
// synthetic attestation is well-formed and internally consistent but is not
// chained to the pinned AWS Nitro root, so acceptance here would mean the
// chain check is not load-bearing.
import { describe, expect, it } from "vitest";
import { verifyBootProof } from "../../src/attestation/boot-proof.js";
import { assertCertValidAt } from "../../src/attestation/turnkey.js";
import {
  appProof,
  bootProof,
  EXPECTED_PCRS,
  MANIFEST_DIGEST,
  NOW_MS,
} from "./boot-proof.testkit.js";
import { encodeLowerHex } from "../../src/wire/hex.js";

function derTlv(tag: number, value: Uint8Array): Uint8Array {
  const len = value.length;
  const header =
    len < 128
      ? [tag, len]
      : len < 256
        ? [tag, 0x81, len]
        : [tag, 0x82, len >> 8, len & 0xff];
  return Uint8Array.of(...header, ...value);
}

function syntheticCertWithValidity(notBefore: Uint8Array, notAfter: Uint8Array): Uint8Array {
  const version = derTlv(0xa0, derTlv(0x02, Uint8Array.of(2)));
  const serial = derTlv(0x02, Uint8Array.of(1));
  const sigAlg = derTlv(0x30, Uint8Array.of());
  const issuer = derTlv(0x30, Uint8Array.of());
  const validity = derTlv(0x30, Uint8Array.of(...notBefore, ...notAfter));
  const tbs = derTlv(0x30, Uint8Array.of(...version, ...serial, ...sigAlg, ...issuer, ...validity));
  return derTlv(0x30, tbs);
}

describe("Boot Proof AWS Nitro chain", () => {
  it("fails closed on an attestation that is not chained to the pinned AWS root", async () => {
    await expect(
      verifyBootProof({
        ephemeralPublicKey: appProof().publicKey,
        bootProof: bootProof(),
        expectedManifestSha256: encodeLowerHex(MANIFEST_DIGEST),
        expectedPcrs: EXPECTED_PCRS,
        nowMs: NOW_MS,
      }),
    ).rejects.toMatchObject({
      code: "BootProofUnverified",
      message: "BootProofUnverified: aws-chain",
    });
  });

  it("enforces X.509 leaf and intermediate validity windows at the attestation timestamp", () => {
    const enc = new TextEncoder();
    const utcCert = syntheticCertWithValidity(
      derTlv(0x17, enc.encode("250101000000Z")),
      derTlv(0x17, enc.encode("250101030000Z")),
    );
    const startMs = Date.UTC(2025, 0, 1, 0, 0, 0);
    const endMs = Date.UTC(2025, 0, 1, 3, 0, 0);
    expect(() => assertCertValidAt(utcCert, startMs)).not.toThrow();
    expect(() => assertCertValidAt(utcCert, endMs)).not.toThrow();
    expect(() => assertCertValidAt(utcCert, startMs - 1)).toThrow();
    expect(() => assertCertValidAt(utcCert, endMs + 1)).toThrow();

    const genCert = syntheticCertWithValidity(
      derTlv(0x18, enc.encode("20500101000000Z")),
      derTlv(0x18, enc.encode("20510101000000Z")),
    );
    expect(() => assertCertValidAt(genCert, Date.UTC(2050, 6, 1))).not.toThrow();
    expect(() => assertCertValidAt(genCert, Date.UTC(2049, 11, 31, 23, 59, 59))).toThrow();
  });
});
