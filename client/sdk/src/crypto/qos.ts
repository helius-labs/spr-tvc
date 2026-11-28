import { gcm } from "@noble/ciphers/aes";
import { p256 } from "@noble/curves/p256";
import { encryptToQuorumKey } from "../attestation/turnkey.js";
import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha512";
import {
  AES_GCM_NONCE_LEN,
  AES_GCM_TAG_LEN,
  QOS_ENCRYPTION_HMAC_MESSAGE,
  QOS_ENVELOPE_LEN_FIELD_LEN,
  QOS_ENVELOPE_OVERHEAD,
  QOS_P256_PUBLIC_LEN,
  SEC1_UNCOMPRESSED_LEN,
  SHA256_LEN,
} from "../wire/constants.js";
import { DecryptionServiceError } from "../wire/error.js";
import { parseUncompressedSec1 } from "./p256.js";

const te = new TextEncoder();
const SEC1_PREFIX_LEN = 1;
const ENVELOPE_HEADER_LEN = QOS_ENVELOPE_OVERHEAD - AES_GCM_TAG_LEN;
const SEALED_LEN_OFFSET = ENVELOPE_HEADER_LEN - QOS_ENVELOPE_LEN_FIELD_LEN;

type QosP256Public = {
  encryption: Uint8Array;
  signing: Uint8Array;
};

export function parseQosP256Public(bytes: Uint8Array): QosP256Public {
  if (bytes.length !== QOS_P256_PUBLIC_LEN) {
    throw new DecryptionServiceError("InvalidPublicKey");
  }
  const encryption = parseUncompressedSec1(
    bytes.slice(0, SEC1_UNCOMPRESSED_LEN)
  );
  const signing = parseUncompressedSec1(bytes.slice(SEC1_UNCOMPRESSED_LEN));
  return { encryption, signing };
}

function sharedX(secret: Uint8Array, publicSec1: Uint8Array): Uint8Array {
  const shared = p256.getSharedSecret(secret, publicSec1, false);
  return shared.slice(SEC1_PREFIX_LEN, SEC1_PREFIX_LEN + SHA256_LEN);
}

function cipherKey(
  ephemeralPublic: Uint8Array,
  receiverPublic: Uint8Array,
  sharedSecret: Uint8Array
): Uint8Array {
  const preImage = new Uint8Array(
    ephemeralPublic.length + receiverPublic.length + sharedSecret.length
  );
  preImage.set(ephemeralPublic, 0);
  preImage.set(receiverPublic, ephemeralPublic.length);
  preImage.set(sharedSecret, ephemeralPublic.length + receiverPublic.length);
  return hmac(sha512, preImage, te.encode(QOS_ENCRYPTION_HMAC_MESSAGE)).slice(
    0,
    SHA256_LEN
  );
}

function aad(
  ephemeralPublic: Uint8Array,
  receiverPublic: Uint8Array
): Uint8Array {
  const out = new Uint8Array(
    ephemeralPublic.length + receiverPublic.length + 2
  );
  out.set(ephemeralPublic, 0);
  out[ephemeralPublic.length] = ephemeralPublic.length;
  out.set(receiverPublic, ephemeralPublic.length + 1);
  out[out.length - 1] = receiverPublic.length;
  return out;
}

function encodeU32Le(value: number): Uint8Array {
  const out = new Uint8Array(QOS_ENVELOPE_LEN_FIELD_LEN);
  const view = new DataView(out.buffer);
  view.setUint32(0, value, true);
  return out;
}

function encodeQosEnvelope(
  nonce: Uint8Array,
  ephemeralPublic: Uint8Array,
  encryptedMessage: Uint8Array
): Uint8Array {
  if (nonce.length !== AES_GCM_NONCE_LEN || ephemeralPublic.length !== SEC1_UNCOMPRESSED_LEN) {
    throw new DecryptionServiceError("InvalidEncryptedEnvelope");
  }
  const out = new Uint8Array(ENVELOPE_HEADER_LEN + encryptedMessage.length);
  out.set(nonce, 0);
  out.set(ephemeralPublic, AES_GCM_NONCE_LEN);
  out.set(encodeU32Le(encryptedMessage.length), SEALED_LEN_OFFSET);
  out.set(encryptedMessage, ENVELOPE_HEADER_LEN);
  return out;
}

function decodeQosEnvelope(bytes: Uint8Array): {
  nonce: Uint8Array;
  ephemeralSenderPublic: Uint8Array;
  encryptedMessage: Uint8Array;
} {
  if (bytes.length < ENVELOPE_HEADER_LEN) throw new DecryptionServiceError("InvalidEncryptedEnvelope");
  const frame = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const messageLen = frame.getUint32(SEALED_LEN_OFFSET, true);
  if (messageLen < AES_GCM_TAG_LEN || bytes.length !== ENVELOPE_HEADER_LEN + messageLen) {
    throw new DecryptionServiceError("InvalidEncryptedEnvelope");
  }
  return {
    nonce: bytes.slice(0, AES_GCM_NONCE_LEN),
    ephemeralSenderPublic: bytes.slice(AES_GCM_NONCE_LEN, SEALED_LEN_OFFSET),
    encryptedMessage: bytes.slice(ENVELOPE_HEADER_LEN),
  };
}

export function qosEncryptWith(
  receiverEncryptionSec1: Uint8Array,
  plaintext: Uint8Array,
  ephemeralSecret: Uint8Array,
  nonce: Uint8Array
): Uint8Array {
  if (nonce.length !== AES_GCM_NONCE_LEN) {
    throw new DecryptionServiceError("InvalidEncryptedEnvelope");
  }
  const receiver = parseUncompressedSec1(receiverEncryptionSec1);
  const ephemeralPublic = p256.getPublicKey(ephemeralSecret, false);
  const shared = sharedX(ephemeralSecret, receiver);
  const key = cipherKey(ephemeralPublic, receiver, shared);
  const associated = aad(ephemeralPublic, receiver);
  const encryptedMessage = gcm(key, nonce, associated).encrypt(plaintext);
  return encodeQosEnvelope(nonce, ephemeralPublic, encryptedMessage);
}

/** Encrypts to a quorum encryption key with Turnkey's QOS envelope. */
export function qosEncrypt(
  receiverEncryptionSec1: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  return encryptToQuorumKey(receiverEncryptionSec1, plaintext);
}

export function qosDecrypt(
  receiverSecret: Uint8Array,
  envelopeBytes: Uint8Array
): Uint8Array {
  const envelope = decodeQosEnvelope(envelopeBytes);
  parseUncompressedSec1(envelope.ephemeralSenderPublic);
  const receiverPublic = p256.getPublicKey(receiverSecret, false);
  const shared = sharedX(receiverSecret, envelope.ephemeralSenderPublic);
  const key = cipherKey(envelope.ephemeralSenderPublic, receiverPublic, shared);
  const associated = aad(envelope.ephemeralSenderPublic, receiverPublic);
  try {
    return gcm(key, envelope.nonce, associated).decrypt(
      envelope.encryptedMessage
    );
  } catch {
    throw new DecryptionServiceError("InvalidEncryptedEnvelope");
  }
}
