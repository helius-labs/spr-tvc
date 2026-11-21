import { sha384 } from "@noble/hashes/sha512";
import { DecryptionServiceError } from "../protocol/error.js";
import {
  MAX_CLOCK_SKEW_MS,
  SHA256_LEN,
  SHA384_LEN,
} from "../protocol/constants.js";
import { bytesEqual, decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import {
  type CborValue,
  decodeAwsNitroAttestationCbor,
  decodeCbor,
} from "./cbor.js";
import {
  type TurnkeyBootProofWire,
  verifyTurnkeyAwsAttestation,
} from "./turnkey.js";

import { verifyAwsNitroAttestation, type CoseSign1 } from "./aws-nitro.js";
import { parseQosP256Public } from "../crypto/qos.js";
import type { NitroPcrs } from "./nitro-policy.js";

const QOS_LIVE_MANIFEST_PCR_COMMITMENT_DOMAIN = "qos-live-manifest-pcr-commitment-v1";
const QOS_LIVE_MANIFEST_COMMITMENT_PCR_INDEX = 17;
const QOS_ATTESTABLE_PCR_COUNT = 32;
const QOS_EPHEMERAL_PUBLIC_KEY_LENGTH = 130;

type QosIdentityPcrIndex = 0 | 1 | 2 | 3;

/**
 * Independently trusted Nitro measurements for the expected QOS deployment.
 * Never populate these values from `/v1/info` or from the Boot Proof itself.
 */
export type QosIdentityPcrs = Readonly<Record<QosIdentityPcrIndex, string>>;

type VerifyBootProofInput = {
  /** Public key from a previously signature-checked App Proof. */
  ephemeralPublicKey: string;
  bootProof: TurnkeyBootProofWire;
  allowedManifestSha256: readonly string[];
  expectedPcrs: QosIdentityPcrs;
  /** Verifier clock. Rejects future attestations and validates the certificate chain now. */
  nowMs: bigint;
};

type AwsNitroAttestationDocument = Map<string | number, CborValue>;

type DecodedBootProof = {
  coseSign1: CoseSign1;
  unprotected: CborValue | undefined;
  attestation: AwsNitroAttestationDocument;
  certificate: Uint8Array;
  cabundle: Uint8Array[];
};

/**
 * Verifies a replica's Boot Proof with Turnkey's AWS Nitro helpers plus
 * independently pinned QOS manifest/PCR checks.
 */
export async function verifyBootProof(input: VerifyBootProofInput): Promise<void> {
  let stage = "decode";
  try {
    const decoded = decodeBootProof(input.bootProof);
    stage = "shape";
    validateAttestationShape(decoded.attestation);
    stage = "timestamp";
    assertAttestationFreshness(decoded.attestation, input.nowMs);

    stage = "bindings";
    verifyProofBindings(input, decoded.attestation);

    // Check certificate validity on the verifier's clock.
    stage = "aws-chain";
    await verifyTurnkeyAwsAttestation(
      decoded.coseSign1,
      decoded.certificate,
      decoded.cabundle,
      Number(input.nowMs),
    );
  } catch {
    // Stage names contain no proof bytes or remote error text. They make a
    // fail-closed deployment diagnosable without widening the public error
    // code or leaking attestation material into application logs.
    throw new DecryptionServiceError("BootProofUnverified", stage);
  }
}

/** Verifies fresh native Nitro evidence with PCRs pinned independently of the endpoint. */
export async function verifyNativeNitroEvidence(
  document: Uint8Array,
  nonce: Uint8Array,
  discoveryBinding: Uint8Array,
  expectedPcrs: NitroPcrs,
  nowMs: bigint,
): Promise<string> {
  try {
    const decoded = decodeAttestation(document);
    const attestation = decoded.attestation;
    validateAwsAttestationShape(attestation);
    assertAttestationFreshness(attestation, nowMs);
    const timestamp = BigInt(attestation.get("timestamp") as number);
    if (!(decoded.unprotected instanceof Map) || decoded.unprotected.size !== 0 ||
      nowMs - timestamp > MAX_CLOCK_SKEW_MS ||
      !bytesEqual(nonce, asBytes(attestation.get("nonce"))) ||
      !bytesEqual(discoveryBinding, asBytes(attestation.get("user_data")))) {
      throw new DecryptionServiceError("BootProofUnverified");
    }
    verifyIdentityPcrs(attestation, expectedPcrs);
    const publicKey = asBytes(attestation.get("public_key"));
    if (publicKey.length !== QOS_EPHEMERAL_PUBLIC_KEY_LENGTH) {
      throw new DecryptionServiceError("BootProofUnverified");
    }
    parseQosP256Public(publicKey);
    await verifyAwsNitroAttestation(decoded.coseSign1, decoded.certificate, decoded.cabundle, Number(nowMs));
    return encodeLowerHex(publicKey);
  } catch {
    throw new DecryptionServiceError("BootProofUnverified");
  }
}

export function computeQosLiveManifestCommitmentPcr(
  manifestDigest: Uint8Array,
  ephemeralPublicKey: Uint8Array,
): Uint8Array {
  if (manifestDigest.length !== SHA256_LEN) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  if (ephemeralPublicKey.length !== QOS_EPHEMERAL_PUBLIC_KEY_LENGTH) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  const commitmentPreimage = new TextEncoder().encode(
    `{"domain":"${QOS_LIVE_MANIFEST_PCR_COMMITMENT_DOMAIN}","ephemeralPublicKey":"${encodeLowerHex(
      ephemeralPublicKey,
    )}","manifestHash":"${encodeLowerHex(manifestDigest)}"}`,
  );
  const commitment = sha384(commitmentPreimage);
  const extensionInput = new Uint8Array(SHA384_LEN + commitment.length);
  extensionInput.set(commitment, SHA384_LEN);
  return sha384(extensionInput);
}

function decodeBootProof(bootProof: TurnkeyBootProofWire): DecodedBootProof {
  return decodeAttestation(decodeBase64(bootProof.awsAttestationDocB64));
}

function decodeAttestation(document: Uint8Array): DecodedBootProof {
  const decodedCose = decodeCbor(document);
  if (!Array.isArray(decodedCose) || decodedCose.length !== 4) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  const [protectedHeaders, unprotected, payload, signature] = decodedCose;
  const coseSign1: CoseSign1 = {
    protectedHeaders: asBytes(protectedHeaders),
    payload: asBytes(payload),
    signature: asBytes(signature),
  };
  const decoded = decodeAwsNitroAttestationCbor(coseSign1.payload);
  if (!(decoded instanceof Map)) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  const certificate = asBytes(decoded.get("certificate"));
  const cabundle = decoded.get("cabundle");
  if (!Array.isArray(cabundle) || cabundle.length === 0) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  return { coseSign1, unprotected, attestation: decoded, certificate, cabundle: cabundle.map(asBytes) };
}

function validateAwsAttestationShape(attestation: AwsNitroAttestationDocument): void {
  const moduleId = attestation.get("module_id");
  if (typeof moduleId !== "string" || moduleId.length === 0) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  if (attestation.get("digest") !== "SHA384") {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  const timestamp = attestation.get("timestamp");
  if (typeof timestamp !== "number" || !Number.isSafeInteger(timestamp) || timestamp <= 0) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
}

function validateAttestationShape(attestation: AwsNitroAttestationDocument): void {
  validateAwsAttestationShape(attestation);
  const nonce = attestation.get("nonce");
  if (nonce !== null && nonce !== undefined) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  const pcrs = attestation.get("pcrs");
  if (!(pcrs instanceof Map) || pcrs.size !== QOS_ATTESTABLE_PCR_COUNT) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  for (let index = 0; index < QOS_ATTESTABLE_PCR_COUNT; index += 1) {
    getPcr(attestation, index);
  }
}

function assertAttestationFreshness(
  attestation: AwsNitroAttestationDocument,
  nowMs: bigint,
): void {
  // Narrowed to Number below for the certificate-chain check, so anything past
  // the safe-integer range would silently lose precision.
  if (nowMs <= 0n || nowMs > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  const timestamp = BigInt(attestation.get("timestamp") as number);
  // The signed challenge or operation reply proves live possession of the key.
  if (timestamp > nowMs + MAX_CLOCK_SKEW_MS) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
}

function verifyProofBindings(
  input: VerifyBootProofInput,
  attestation: AwsNitroAttestationDocument,
): void {
  if (input.allowedManifestSha256.length === 0) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  const allowed = input.allowedManifestSha256.map((value) =>
    decodeFixedLowerHex(value, SHA256_LEN),
  );
  // QOS puts the canonical JSON manifest digest in the attested user data.
  const manifestDigest = asBytes(attestation.get("user_data"));
  if (
    manifestDigest.length !== SHA256_LEN ||
    !allowed.some((digest) => bytesEqual(digest, manifestDigest))
  ) {
    throw new DecryptionServiceError("BootProofUnverified");
  }

  const attestedPublicKey = asBytes(attestation.get("public_key"));
  if (attestedPublicKey.length !== QOS_EPHEMERAL_PUBLIC_KEY_LENGTH) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  const appPublicKey = decodeFixedLowerHex(
    input.ephemeralPublicKey,
    QOS_EPHEMERAL_PUBLIC_KEY_LENGTH,
  );
  const bootPublicKey = decodeFixedLowerHex(
    input.bootProof.ephemeralPublicKeyHex,
    QOS_EPHEMERAL_PUBLIC_KEY_LENGTH,
  );
  if (!bytesEqual(appPublicKey, bootPublicKey) || !bytesEqual(bootPublicKey, attestedPublicKey)) {
    throw new DecryptionServiceError("BootProofUnverified");
  }

  verifyIdentityPcrs(attestation, input.expectedPcrs);

  const expectedLivePcr = computeQosLiveManifestCommitmentPcr(manifestDigest, attestedPublicKey);
  if (!bytesEqual(expectedLivePcr, getPcr(attestation, QOS_LIVE_MANIFEST_COMMITMENT_PCR_INDEX))) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
}

function verifyIdentityPcrs(attestation: AwsNitroAttestationDocument, expectedPcrs: QosIdentityPcrs): void {
  for (const index of [0, 1, 2, 3] as const) {
    const expected = decodeFixedLowerHex(expectedPcrs[index], SHA384_LEN);
    if (!bytesEqual(expected, getPcr(attestation, index))) {
      throw new DecryptionServiceError("BootProofUnverified");
    }
  }
}

function getPcr(attestation: AwsNitroAttestationDocument, index: number): Uint8Array {
  // NSM keys the PCR map by CBOR unsigned integer, so the lookup is by number.
  // A text-keyed map is outside the format and is rejected here.
  const pcrs = attestation.get("pcrs");
  if (!(pcrs instanceof Map)) throw new DecryptionServiceError("BootProofUnverified");
  const bytes = asBytes(pcrs.get(index));
  if (bytes.length !== SHA384_LEN) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  return bytes;
}

function decodeFixedLowerHex(value: string, length: number): Uint8Array {
  const bytes = decodeLowerHex(value);
  if (bytes.length !== length) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  return bytes;
}

function decodeBase64(value: string): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    throw new DecryptionServiceError("BootProofUnverified");
  }
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function asBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  throw new DecryptionServiceError("BootProofUnverified");
}
