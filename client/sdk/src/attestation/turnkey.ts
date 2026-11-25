// The COSE signature and the Nitro certificate chain are Turnkey's verifier.
// boot-proof.ts still pins the replica key, PCR0–3, PCR17, and the manifest
// digest. Turnkey's `verify` does not, and it also requires a `timestampMs`
// field our proofs do not carry.

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
): Promise<void> {
  await verifyCoseSign1Sig(
    [coseSign1.protectedHeaders, new Uint8Array(0), coseSign1.payload, coseSign1.signature],
    certificate,
  );
  await verifyCertificateChain(cabundle, AWS_NITRO_ROOT_CERT_PEM, certificate, timestampMs);
}
