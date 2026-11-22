import * as x509 from "@peculiar/x509";
import { bytesEqual } from "../protocol/hex.js";
import { decodeCbor, encodeCoseSigStructure } from "./cbor.js";

export const AWS_NITRO_ROOT_CERT_PEM = `-----BEGIN CERTIFICATE-----
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

export async function verifyCoseSign1Signature(
  coseSign1: CoseSign1,
  leaf: Uint8Array,
  cryptoInstance: Crypto,
): Promise<void> {
  // ES384 is fixed by this verifier rather than read from the protected
  // header, so a document cannot negotiate a weaker algorithm.
  const tbs = encodeCoseSigStructure(
    coseSign1.protectedHeaders,
    new Uint8Array(0),
    coseSign1.payload
  );
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

/** AWS supplies its bundle in root-to-leaf order. Verify it against the exact pinned root. */
export async function verifyAwsNitroAttestation(
  cose: CoseSign1, certificate: Uint8Array, cabundle: Uint8Array[], nowMs: number,
) {
  const headers = decodeCbor(cose.protectedHeaders);
  if (!(headers instanceof Map) || headers.size !== 1 || headers.get(1) !== -35 ||
      cose.signature.length !== 96) throw new Error("Invalid AWS Nitro COSE headers");

  const root = new x509.X509Certificate(AWS_NITRO_ROOT_CERT_PEM);
  if (!cabundle[0] || cabundle.length > 8 ||
      !bytesEqual(new Uint8Array(root.rawData), cabundle[0])) throw new Error("Untrusted AWS Nitro root");
  const encoded = [...cabundle.slice(1), certificate];
  if (encoded.some(der => der.length === 0 || der.length > 1024)) throw new Error("Invalid Nitro certificate size");
  const chain = [root, ...encoded.map(der => new x509.X509Certificate(exactArrayBuffer(der)))];
  const date = new Date(nowMs);
  let notBefore = root.notBefore.getTime();
  let notAfter = root.notAfter.getTime();
  for (let index = 0; index < chain.length; index++) {
    const cert = chain[index]!;
    const issuer = chain[Math.max(0, index - 1)]!;
    const isCa = index < chain.length - 1;
    const constraints = cert.getExtension(x509.BasicConstraintsExtension);
    const expectedUsage = isCa ? x509.KeyUsageFlags.keyCertSign : x509.KeyUsageFlags.digitalSignature;
    const usage = cert.getExtension(x509.KeyUsagesExtension);
    if (cert.extensions.some(extension => extension.critical &&
          !(extension instanceof x509.BasicConstraintsExtension || extension instanceof x509.KeyUsagesExtension)) ||
        cert.issuer !== issuer.subject ||
        (isCa ? !constraints?.ca || !constraints.critical : constraints?.ca === true) ||
        (isCa && constraints?.pathLength !== undefined && constraints.pathLength < chain.length - index - 2) ||
        !usage || (usage.usages & expectedUsage) === 0 ||
        !(await cert.verify({ publicKey: issuer.publicKey, date }, crypto))) {
      throw new Error("Invalid AWS Nitro certificate chain");
    }
    notBefore = Math.max(notBefore, cert.notBefore.getTime());
    notAfter = Math.min(notAfter, cert.notAfter.getTime());
  }
  await verifyCoseSign1Signature(cose, certificate, crypto);
  // X509Certificate.verify uses an open interval at both ends.
  return { certificateValidFromMs: BigInt(notBefore) + 1n, certificateValidThroughMs: BigInt(notAfter) - 1n };
}
