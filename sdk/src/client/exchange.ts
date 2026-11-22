import type { Bytes32 } from "@heliuslabs/spr";
import { X25519PublicKey } from "@heliuslabs/spr/keypair";
import { BN254_MODULUS_DEC } from "@heliuslabs/spr/transaction";
import { p256 } from "@noble/curves/p256";
import { createSignableMessage, getAddressEncoder, type MessagePartialSigner } from "@solana/kit";

import type { ConnectedTvcRuntime } from "../connection/connect.js";
import {
  checkSignedRequestSize,
  requireCurrentReleasePolicy,
  sealedExchange,
} from "../connection/operations.js";
import { awaitWithSignal } from "../connection/request.js";
import { API_VERSION } from "../protocol/constants.js";
import { DecryptionServiceError } from "../protocol/error.js";
import { encodeLowerHex, requireHex } from "../protocol/hex.js";
import { parseStrictJson } from "../protocol/json.js";
import type { DecryptItem } from "../protocol/types.js";
import {
  decryptMessage,
  serviceRequestDigest,
  type ServiceOperation,
  type ServiceRequest,
  type ServiceResult,
} from "../protocol/decryption.js";

const ED25519_SIGNATURE_BYTES = 64;
const BN254_MODULUS = BigInt(BN254_MODULUS_DEC);
const EMPTY_SIGNATURE = "00".repeat(ED25519_SIGNATURE_BYTES);
const OPERATION_KINDS = { PublicKeys: "ServicePublicKeys", Decrypt: "ServiceDecrypt" } as const;
const RESULT_KEYS = {
  PublicKeys: ["type", "viewing_public_key", "nullifier_public_key"],
  Decrypt: ["type", "nullifier_secret", "plaintexts"],
} as const;

const addressEncoder = getAddressEncoder();

type DecryptCall = {
  readonly type: "Decrypt";
  readonly owner: MessagePartialSigner;
  readonly items: readonly DecryptItem[];
};

export type ServiceCall = Extract<ServiceOperation, { type: "PublicKeys" }> | DecryptCall;
export type ServiceCallResult<T extends ServiceCall> = Extract<ServiceResult, { type: T["type"] }>;

export function decodePublicKeys(result: Extract<ServiceResult, { type: "PublicKeys" }>) {
  const nullifierPublicKey = requireHex(result.nullifier_public_key, 32) as Bytes32;
  if (BigInt(`0x${result.nullifier_public_key}`) >= BN254_MODULUS) {
    throw new DecryptionServiceError("InvalidPublicKey", "expected a canonical BN254 nullifier public key");
  }
  const viewingPublicKey = X25519PublicKey.fromBytes(requireHex(result.viewing_public_key, 33));
  return { nullifierPublicKey, viewingPublicKey };
}

async function signBeforeReleaseExpires(
  owner: MessagePartialSigner,
  message: Uint8Array,
  context: ConnectedTvcRuntime,
  signal: AbortSignal,
) {
  const now = context.nowMs();
  requireCurrentReleasePolicy(context, now);
  signal.throwIfAborted();
  const controller = new AbortController();
  const approvalSignal = AbortSignal.any([signal, controller.signal]);
  const remaining = Number(context.releasePolicyExpiresAtMs - now + 1n);
  const timer = setTimeout(() => controller.abort(new DecryptionServiceError("ExpiredRequest")),
    Math.min(remaining, 2_147_483_647));
  try {
    return await awaitWithSignal(
      owner.signMessages([createSignableMessage(message)], { abortSignal: approvalSignal }),
      approvalSignal,
    );
  } finally {
    clearTimeout(timer);
  }
}

/** Bind the release and response key before asking the owner to authorize a batch. */
export async function executeServiceCall<T extends ServiceCall>(
  context: ConnectedTvcRuntime,
  call: T,
  signal: AbortSignal,
): Promise<ServiceCallResult<T>> {
  const { info } = context;
  signal.throwIfAborted();
  if (context.requireCurrentCheckpoint) await context.requireCurrentCheckpoint(signal);
  requireCurrentReleasePolicy(context, context.nowMs());
  const responseSecret = p256.utils.randomPrivateKey();
  try {
    const { owner, operation } = call.type === "Decrypt"
      ? {
          owner: call.owner,
          operation: {
            type: "Decrypt" as const,
            signer: call.owner.address,
            signature: EMPTY_SIGNATURE,
            items: call.items,
          },
        }
      : { owner: undefined, operation: call };
    let request: ServiceRequest = {
      version: API_VERSION,
      request_id: encodeLowerHex(crypto.getRandomValues(new Uint8Array(32))),
      target_release_id: info.release_id,
      target_manifest_digest: info.manifest_digest,
      target_executable_digest: info.executable_digest,
      quorum_key_id: info.quorum_key_id,
      quorum_key_epoch: info.quorum_key_epoch,
      client_response_public_key: encodeLowerHex(p256.getPublicKey(responseSecret, false)),
      operation,
    };
    const requestDigest = serviceRequestDigest(request);
    checkSignedRequestSize(context, request);
    if (owner) {
      const address = operation.signer;
      const message = decryptMessage(
        new Uint8Array(addressEncoder.encode(address)),
        info.network,
        requestDigest,
      );
      const [signatures] = await signBeforeReleaseExpires(owner, message, context, signal);
      const signature = signatures?.[address];
      if (signature?.length !== ED25519_SIGNATURE_BYTES) {
        throw new DecryptionServiceError("InvalidSignature");
      }
      request = { ...request, operation: { ...operation, signature: encodeLowerHex(signature) } };
      if (context.requireCurrentCheckpoint) await context.requireCurrentCheckpoint(signal);
    }

    const plaintext = await sealedExchange(context, {
      request,
      requestDigest,
      responseSecret,
      operation: OPERATION_KINDS[call.type],
    }, signal);
    const result = parseStrictJson<ServiceResult>(plaintext, RESULT_KEYS[call.type]);
    if (result.type !== call.type) throw new DecryptionServiceError("ReleaseBindingMismatch");
    return result as ServiceCallResult<T>;
  } finally {
    responseSecret.fill(0);
  }
}
