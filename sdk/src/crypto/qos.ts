import { gcm } from "@noble/ciphers/aes";
import { p256 } from "@noble/curves/p256";
import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha512";
import {
  AES_GCM_NONCE_LEN,
  AES_GCM_TAG_LEN,
  QOS_ENCRYPTION_HMAC_MESSAGE,
  QOS_P256_PUBLIC_LEN,
  SEC1_UNCOMPRESSED_LEN,
} from "../protocol/constants.js";
import { DecryptionServiceError } from "../protocol/error.js";
import { parseUncompressedSec1 } from "./p256.js";

const te = new TextEncoder();
const ENVELOPE_HEADER_LEN = AES_GCM_NONCE_LEN + SEC1_UNCOMPRESSED_LEN + 4;

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

function keyMaterial(
  ephemeralPublic: Uint8Array,
  receiverPublic: Uint8Array,
  secret: Uint8Array,
  peer: Uint8Array,
): Uint8Array {
  const preImage = new Uint8Array(ephemeralPublic.length + receiverPublic.length + 32);
  const shared = p256.getSharedSecret(secret, peer, false);
  try {
    preImage.set(ephemeralPublic);
    preImage.set(receiverPublic, ephemeralPublic.length);
    preImage.set(shared.subarray(1, 33), ephemeralPublic.length + receiverPublic.length);
    return hmac(sha512, preImage, te.encode(QOS_ENCRYPTION_HMAC_MESSAGE));
  } finally {
    shared.fill(0);
    preImage.fill(0);
  }
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
  const out = new Uint8Array(4);
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
  out.set(encodeU32Le(encryptedMessage.length), AES_GCM_NONCE_LEN + SEC1_UNCOMPRESSED_LEN);
  out.set(encryptedMessage, ENVELOPE_HEADER_LEN);
  return out;
}

function decodeQosEnvelope(bytes: Uint8Array): {
  nonce: Uint8Array;
  ephemeralSenderPublic: Uint8Array;
  encryptedMessage: Uint8Array;
} {
  if (bytes.length < ENVELOPE_HEADER_LEN) throw new DecryptionServiceError("InvalidEncryptedEnvelope");
  const lengthOffset = AES_GCM_NONCE_LEN + SEC1_UNCOMPRESSED_LEN;
  const frame = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const messageLen = frame.getUint32(lengthOffset, true);
  if (messageLen < AES_GCM_TAG_LEN || bytes.length !== ENVELOPE_HEADER_LEN + messageLen) {
    throw new DecryptionServiceError("InvalidEncryptedEnvelope");
  }
  return {
    nonce: bytes.slice(0, AES_GCM_NONCE_LEN),
    ephemeralSenderPublic: bytes.slice(AES_GCM_NONCE_LEN, lengthOffset),
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
  const material = keyMaterial(ephemeralPublic, receiver, ephemeralSecret, receiver);
  try {
    const associated = aad(ephemeralPublic, receiver);
    const encryptedMessage = gcm(material.subarray(0, 32), nonce, associated).encrypt(plaintext);
    return encodeQosEnvelope(nonce, ephemeralPublic, encryptedMessage);
  } finally {
    material.fill(0);
  }
}

export function qosEncrypt(
  receiverEncryptionSec1: Uint8Array,
  plaintext: Uint8Array
): Uint8Array {
  const nonce = crypto.getRandomValues(new Uint8Array(AES_GCM_NONCE_LEN));
  const ephemeral = p256.utils.randomPrivateKey();
  try {
    return qosEncryptWith(receiverEncryptionSec1, plaintext, ephemeral, nonce);
  } finally {
    ephemeral.fill(0);
  }
}

export function qosDecrypt(
  receiverSecret: Uint8Array,
  envelopeBytes: Uint8Array
): Uint8Array {
  const envelope = decodeQosEnvelope(envelopeBytes);
  parseUncompressedSec1(envelope.ephemeralSenderPublic);
  const receiverPublic = p256.getPublicKey(receiverSecret, false);
  const material = keyMaterial(envelope.ephemeralSenderPublic, receiverPublic, receiverSecret, envelope.ephemeralSenderPublic);
  try {
    const associated = aad(envelope.ephemeralSenderPublic, receiverPublic);
    return gcm(material.subarray(0, 32), envelope.nonce, associated).decrypt(envelope.encryptedMessage);
  } catch {
    throw new DecryptionServiceError("InvalidEncryptedEnvelope");
  } finally {
    material.fill(0);
  }
}
