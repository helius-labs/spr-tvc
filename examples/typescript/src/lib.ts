import { ViewingKey, type DecryptRequest } from "@heliuslabs/spr";
import { randomSalt, type X25519PublicKey } from "@heliuslabs/spr/keypair";
import { generateKeyPairSigner, type KeyPairSigner } from "@solana/kit";
import type { DecryptionService } from "@heliuslabs/spr-decryption-service";
import { createLocalDecryptionService } from "@heliuslabs/spr-decryption-service/testing";

export function endpoint(): URL {
  const value = process.env["DECRYPTION_SERVICE_LOCAL_ENDPOINT"];
  if (value === undefined) {
    console.error("Set DECRYPTION_SERVICE_LOCAL_ENDPOINT to the loopback enclave.");
    process.exit(1);
  }
  return new URL(value);
}

export function localService(): DecryptionService {
  return createLocalDecryptionService({ network: "devnet", endpoint: endpoint() });
}

export async function owner(): Promise<KeyPairSigner> {
  return generateKeyPairSigner();
}

export function lowerHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** One transfer note encrypted to the service viewing key. */
export function noteFor(viewingPublicKey: X25519PublicKey, plaintext: Uint8Array, slot: number): DecryptRequest {
  const sender = ViewingKey.generate();
  try {
    const salt = randomSalt();
    return {
      ciphertext: sender.encryptSlot(viewingPublicKey, plaintext, salt, slot),
      viewingPublicKey,
      txViewingPublicKey: sender.publicKey(),
      salt,
      slotIndex: slot,
      label: "transfer",
    };
  } finally {
    sender.destroy();
  }
}

export function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}
