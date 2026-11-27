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
  attestationTimestampMs: number = timestampMs,
): Promise<void> {
  assertCertValidAt(certificate, attestationTimestampMs);
  for (const cert of cabundle) {
    assertCertValidAt(cert, attestationTimestampMs);
  }
  await verifyCoseSign1Sig(
    [coseSign1.protectedHeaders, new Uint8Array(0), coseSign1.payload, coseSign1.signature],
    certificate,
  );
  await verifyCertificateChain(cabundle, AWS_NITRO_ROOT_CERT_PEM, certificate, timestampMs);
}

type DerElement = {
  readonly tag: number;
  readonly value: Uint8Array;
  readonly nextOffset: number;
};

/** Parses the X.509 Validity window from DER and enforces `notBefore <= timestampMs <= notAfter`. */
export function assertCertValidAt(certDer: Uint8Array, timestampMs: number): void {
  if (!Number.isSafeInteger(timestampMs) || timestampMs <= 0) {
    throw new Error("invalid certificate check timestamp");
  }
  const outer = readDerTlv(certDer, 0);
  if (outer.tag !== 0x30 || outer.nextOffset !== certDer.length) {
    throw new Error("invalid certificate SEQUENCE");
  }
  const tbs = readDerTlv(outer.value, 0);
  if (tbs.tag !== 0x30) {
    throw new Error("invalid tbsCertificate SEQUENCE");
  }
  let offset = 0;
  const first = readDerTlv(tbs.value, offset);
  // Optional EXPLICIT [0] version.
  if (first.tag === 0xa0) {
    offset = first.nextOffset;
  }
  // serialNumber (INTEGER), signature (SEQUENCE), issuer (SEQUENCE)
  for (const expectedTag of [0x02, 0x30, 0x30]) {
    const field = readDerTlv(tbs.value, offset);
    if (field.tag !== expectedTag) {
      throw new Error("unexpected tbsCertificate field");
    }
    offset = field.nextOffset;
  }
  const validity = readDerTlv(tbs.value, offset);
  if (validity.tag !== 0x30) {
    throw new Error("missing certificate Validity");
  }
  const notBeforeEl = readDerTlv(validity.value, 0);
  const notAfterEl = readDerTlv(validity.value, notBeforeEl.nextOffset);
  if (notAfterEl.nextOffset !== validity.value.length) {
    throw new Error("trailing bytes in certificate Validity");
  }
  const notBeforeMs = parseDerTime(notBeforeEl);
  const notAfterMs = parseDerTime(notAfterEl);
  if (notBeforeMs > notAfterMs || timestampMs < notBeforeMs || timestampMs > notAfterMs) {
    throw new Error("certificate outside validity window");
  }
}

function readDerTlv(bytes: Uint8Array, offset: number): DerElement {
  if (offset + 2 > bytes.length) {
    throw new Error("truncated DER TLV");
  }
  const tag = bytes[offset]!;
  const lenByte = bytes[offset + 1]!;
  let length: number;
  let valueStart: number;
  if ((lenByte & 0x80) === 0) {
    length = lenByte;
    valueStart = offset + 2;
  } else {
    const numOctets = lenByte & 0x7f;
    if (numOctets === 0 || numOctets > 4 || offset + 2 + numOctets > bytes.length) {
      throw new Error("invalid DER length");
    }
    if (bytes[offset + 2] === 0) {
      throw new Error("non-canonical DER length");
    }
    length = 0;
    for (let i = 0; i < numOctets; i += 1) {
      length = length * 256 + bytes[offset + 2 + i]!;
    }
    if (length < 128) {
      throw new Error("non-canonical DER length");
    }
    valueStart = offset + 2 + numOctets;
  }
  const nextOffset = valueStart + length;
  if (nextOffset > bytes.length) {
    throw new Error("DER element exceeds buffer");
  }
  return { tag, value: bytes.subarray(valueStart, nextOffset), nextOffset };
}

function parseDerTime(element: DerElement): number {
  const text = new TextDecoder("ascii", { fatal: true }).decode(element.value);
  let year: number;
  let rest: string;
  if (element.tag === 0x17) {
    // UTCTime: YYMMDDHHMMSSZ (RFC 5280 Section 4.1.2.5.1)
    if (!/^\d{12}Z$/.test(text)) {
      throw new Error("invalid UTCTime");
    }
    const yy = Number(text.slice(0, 2));
    year = yy >= 50 ? 1900 + yy : 2000 + yy;
    rest = text.slice(2, 12);
  } else if (element.tag === 0x18) {
    // GeneralizedTime: YYYYMMDDHHMMSSZ (RFC 5280 Section 4.1.2.5.2)
    if (!/^\d{14}Z$/.test(text)) {
      throw new Error("invalid GeneralizedTime");
    }
    year = Number(text.slice(0, 4));
    rest = text.slice(4, 14);
  } else {
    throw new Error("unexpected ASN.1 time tag");
  }
  const month = Number(rest.slice(0, 2));
  const day = Number(rest.slice(2, 4));
  const hour = Number(rest.slice(4, 6));
  const minute = Number(rest.slice(6, 8));
  const second = Number(rest.slice(8, 10));
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > 31 ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    throw new Error("invalid ASN.1 time fields");
  }
  const ms = Date.UTC(year, month - 1, day, hour, minute, second);
  const check = new Date(ms);
  if (
    check.getUTCFullYear() !== year ||
    check.getUTCMonth() !== month - 1 ||
    check.getUTCDate() !== day
  ) {
    throw new Error("invalid calendar date");
  }
  return ms;
}
