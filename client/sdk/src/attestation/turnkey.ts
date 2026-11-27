// The COSE signature and the Nitro certificate chain are Turnkey's verifier.
// boot-proof.ts still pins the replica key, PCR0–3, PCR17, and the manifest
// digest. Turnkey's `verify` does not, and it also requires a `timestampMs`
// field our proofs do not carry.

import {
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  X509Certificate,
} from "@peculiar/x509";
import { quorumKeyEncrypt, verifyCertificateChain, verifyCoseSign1Sig } from "@turnkey/crypto";
import type { v1AppProof, v1BootProof } from "@turnkey/sdk-types";

const AWS_NITRO_ROOT_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`;

export type CoseSign1 = {
  readonly protectedHeaders: Uint8Array;
  readonly payload: Uint8Array;
  readonly signature: Uint8Array;
};

export type TurnkeyAppProofWire = v1AppProof;
export type TurnkeyBootProofWire = v1BootProof;

/** QOS envelope for a shared quorum encryption key. Any replica can open it. */
export function encryptToQuorumKey(
  receiverEncryptionSec1: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  return quorumKeyEncrypt(receiverEncryptionSec1, plaintext);
}

export async function verifyTurnkeyAwsAttestation(
  coseSign1: CoseSign1,
  certificate: Uint8Array,
  cabundle: Uint8Array[],
  timestampMs: number,
  attestationTimestampMs: number = timestampMs,
): Promise<void> {
  assertCertValidAt(certificate, attestationTimestampMs, false);
  // cabundle[0] is an untrusted copy of the root; verifyCertificateChain discards it
  // and substitutes AWS_NITRO_ROOT_CERT_PEM, so check only intermediates here.
  for (const intermediate of cabundle.slice(1)) {
    assertCertValidAt(intermediate, attestationTimestampMs, true);
  }
  await verifyCoseSign1Sig(
    [coseSign1.protectedHeaders, new Uint8Array(0), coseSign1.payload, coseSign1.signature],
    certificate,
  );
  await verifyCertificateChain(cabundle, AWS_NITRO_ROOT_CERT_PEM, certificate, timestampMs);
}

/** Enforces X.509 validity at `timestampMs` and, for intermediates, CA constraints. */
export function assertCertValidAt(
  certDer: Uint8Array,
  timestampMs: number,
  requireCa = false,
): void {
  if (!Number.isSafeInteger(timestampMs) || timestampMs <= 0) {
    throw new Error("invalid certificate check timestamp");
  }
  const cert = new X509Certificate(new Uint8Array(certDer));
  const notBeforeMs = cert.notBefore.getTime();
  const notAfterMs = cert.notAfter.getTime();
  if (notBeforeMs > notAfterMs || timestampMs < notBeforeMs || timestampMs > notAfterMs) {
    throw new Error("certificate outside validity window");
  }
  if (requireCa) {
    const basicConstraints = cert.getExtension(BasicConstraintsExtension);
    if (!basicConstraints?.ca) {
      throw new Error("intermediate certificate is not a CA");
    }
    const keyUsage = cert.getExtension(KeyUsagesExtension);
    if (keyUsage && (keyUsage.usages & KeyUsageFlags.keyCertSign) === 0) {
      throw new Error("intermediate certificate lacks keyCertSign");
    }
  }
}
