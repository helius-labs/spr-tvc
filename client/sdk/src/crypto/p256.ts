import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import {
  ASN1_SEQUENCE_TAG,
  RAW_P256_SIGNATURE_LEN,
  SEC1_COMPRESSED_EVEN,
  SEC1_COMPRESSED_LEN,
  SEC1_COMPRESSED_ODD,
  SEC1_UNCOMPRESSED_LEN,
  SEC1_UNCOMPRESSED_PREFIX,
} from "../wire/constants.js";
import { DecryptionServiceError } from "../wire/error.js";

export function parseUncompressedSec1(bytes: Uint8Array): Uint8Array {
  if (
    bytes.length === SEC1_COMPRESSED_LEN &&
    (bytes[0] === SEC1_COMPRESSED_EVEN || bytes[0] === SEC1_COMPRESSED_ODD)
  ) {
    throw new DecryptionServiceError("CompressedKeyRejected");
  }
  if (bytes.length !== SEC1_UNCOMPRESSED_LEN || bytes[0] !== SEC1_UNCOMPRESSED_PREFIX) {
    throw new DecryptionServiceError("InvalidPublicKey");
  }
  try {
    p256.ProjectivePoint.fromHex(bytes);
  } catch {
    throw new DecryptionServiceError("InvalidPublicKey");
  }
  return bytes;
}

function parseRawLowS(signature: Uint8Array) {
  if (signature.length !== RAW_P256_SIGNATURE_LEN) {
    if (signature.length > 0 && signature[0] === ASN1_SEQUENCE_TAG) {
      throw new DecryptionServiceError("DerSignatureRejected");
    }
    throw new DecryptionServiceError("InvalidSignature");
  }
  let sig;
  try {
    sig = p256.Signature.fromCompact(signature);
  } catch {
    throw new DecryptionServiceError("InvalidSignature");
  }
  if (sig.hasHighS()) {
    throw new DecryptionServiceError("HighSSignature");
  }
  return sig;
}

export function signP256Prehash(secret: Uint8Array, digest: Uint8Array): Uint8Array {
  const sig = p256.sign(digest, secret, { lowS: true, prehash: false });
  return sig.toCompactRawBytes();
}

export function verifyP256Prehash(
  publicSec1: Uint8Array,
  digest: Uint8Array,
  signature: Uint8Array,
): void {
  parseUncompressedSec1(publicSec1);
  const sig = parseRawLowS(signature);
  if (!p256.verify(sig, digest, publicSec1, { prehash: false })) {
    throw new DecryptionServiceError("InvalidSignature");
  }
}

export function signP256Message(secret: Uint8Array, message: Uint8Array): Uint8Array {
  return signP256Prehash(secret, sha256(message));
}

export function verifyP256Message(
  publicSec1: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): void {
  verifyP256Prehash(publicSec1, sha256(message), signature);
}
