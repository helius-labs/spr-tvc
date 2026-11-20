// Verify the Nitro COSE signature and certificate chain against the pinned AWS
// root, using the verifier's clock. boot-proof.ts checks the replica key, PCRs,
// and canonical QOS manifest digest against the release policy.

import * as turnkeyCrypto from "@turnkey/crypto";
import type { v1AppProof, v1BootProof } from "@turnkey/sdk-types";
import * as x509 from "@peculiar/x509";

import { encodeCoseSigStructure } from "./cbor.js";

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

export async function verifyTurnkeyAwsAttestation(
  coseSign1: CoseSign1,
  certificate: Uint8Array,
  cabundle: Uint8Array[],
  timestampMs: number
): Promise<void> {
  await verifyCoseSign1Signature(coseSign1, certificate);
  await turnkeyCrypto.verifyCertificateChain(
    cabundle,
    AWS_NITRO_ROOT_CERT_PEM,
    certificate,
    timestampMs
  );
}

async function verifyCoseSign1Signature(
  coseSign1: CoseSign1,
  leaf: Uint8Array
): Promise<void> {
  // ES384 is fixed by this verifier rather than read from the protected
  // header, so a document cannot negotiate a weaker algorithm.
  const tbs = encodeCoseSigStructure(
    coseSign1.protectedHeaders,
    new Uint8Array(0),
    coseSign1.payload
  );
  const cryptoInstance = await turnkeyCrypto.getCryptoInstance();
  const leafCertificate = new x509.X509Certificate(exactArrayBuffer(leaf));
  const publicKey = await cryptoInstance.subtle.importKey(
    "spki",
    leafCertificate.publicKey.rawData,
    { name: "ECDSA", namedCurve: "P-384" },
    false,
    ["verify"]
  );
  const valid = await cryptoInstance.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-384" } },
    publicKey,
    exactArrayBuffer(coseSign1.signature),
    exactArrayBuffer(tbs)
  );
  if (!valid) throw new Error("COSE_Sign1 ES384 verification failed");
}

function exactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}
