// Runs against the real Turnkey/AWS Nitro seam, with nothing mocked. A
// synthetic attestation is well-formed and internally consistent but is not
// chained to the pinned AWS Nitro root, so acceptance here would mean the
// chain check is not load-bearing.
import {
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  X509CertificateGenerator,
} from "@peculiar/x509";
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

async function generateTestCert(options: {
  notBefore: Date;
  notAfter: Date;
  ca?: boolean;
  keyUsages?: KeyUsageFlags;
}): Promise<Uint8Array> {
  const keys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-384" },
    true,
    ["sign", "verify"],
  );
  const extensions = [];
  if (options.ca !== undefined) {
    extensions.push(new BasicConstraintsExtension(options.ca, undefined, true));
  }
  if (options.keyUsages !== undefined) {
    extensions.push(new KeyUsagesExtension(options.keyUsages, true));
  }
  const cert = await X509CertificateGenerator.createSelfSigned({
    name: "CN=test",
    keys,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-384" },
    notBefore: options.notBefore,
    notAfter: options.notAfter,
    extensions,
  });
  return new Uint8Array(cert.rawData);
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

  it("enforces X.509 validity windows and intermediate CA constraints", async () => {
    const startMs = Date.UTC(2025, 0, 1, 0, 0, 0);
    const endMs = Date.UTC(2025, 0, 1, 3, 0, 0);
    const leafCert = await generateTestCert({
      notBefore: new Date(startMs),
      notAfter: new Date(endMs),
      ca: false,
      keyUsages: KeyUsageFlags.digitalSignature,
    });
    expect(() => assertCertValidAt(leafCert, startMs)).not.toThrow();
    expect(() => assertCertValidAt(leafCert, endMs)).not.toThrow();
    expect(() => assertCertValidAt(leafCert, startMs - 1)).toThrow();
    expect(() => assertCertValidAt(leafCert, endMs + 1)).toThrow();
    expect(() => assertCertValidAt(leafCert, startMs, true)).toThrow();

    const genCert = await generateTestCert({
      notBefore: new Date(Date.UTC(2050, 0, 1)),
      notAfter: new Date(Date.UTC(2051, 0, 1)),
      ca: true,
      keyUsages: KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign,
    });
    expect(() => assertCertValidAt(genCert, Date.UTC(2050, 6, 1), true)).not.toThrow();
    expect(() => assertCertValidAt(genCert, Date.UTC(2049, 11, 31, 23, 59, 59), true)).toThrow();

    const noCertSignCa = await generateTestCert({
      notBefore: new Date(startMs),
      notAfter: new Date(endMs),
      ca: true,
      keyUsages: KeyUsageFlags.digitalSignature,
    });
    expect(() => assertCertValidAt(noCertSignCa, startMs, true)).toThrow();
  });
});
