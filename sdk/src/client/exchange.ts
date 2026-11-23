import type { Bytes32 } from "@heliuslabs/spr";
import { X25519PublicKey } from "@heliuslabs/spr/keypair";
import { BN254_MODULUS_DEC } from "@heliuslabs/spr/transaction";
import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/p256";
import { createSignableMessage, getAddressEncoder, type MessagePartialSigner } from "@solana/kit";

import type { ConnectedTvcRuntime } from "../connection/connect.js";
import {
  checkSignedRequestSize,
  remainingReleasePolicyMs,
  requireCurrentReleasePolicy,
  requireOperationPolicy,
  sealedExchange,
} from "../connection/operations.js";
import { awaitWithSignal } from "../connection/request.js";
import { API_VERSION } from "../protocol/constants.js";
import { AuthenticatedOperationError, DecryptionServiceError } from "../protocol/error.js";
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
const OWNER_APPROVAL_MS = 60_000;
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

function verifiesOwnerSignature(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    const owner = ed25519.ExtendedPoint.fromHex(publicKey);
    const nonce = ed25519.ExtendedPoint.fromHex(signature.subarray(0, 32));
    return !owner.isSmallOrder() && owner.isTorsionFree() &&
      !nonce.isSmallOrder() && nonce.isTorsionFree() &&
      ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

function ownerApprovalScope(context: ConnectedTvcRuntime, signal: AbortSignal) {
  const now = context.nowMs();
  const started = performance.now();
  const remaining = Math.floor(Math.min(OWNER_APPROVAL_MS, remainingReleasePolicyMs(context, now)));
  if (!(remaining > 0)) throw new DecryptionServiceError("ExpiredRequest");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new DecryptionServiceError("ExpiredRequest")), remaining);
  return {
    context: {
      ...context,
      releasePolicyExpiresAtMs: now + BigInt(remaining) - 1n,
      policyFreshnessRemainingMs: () => Math.min(
        started + remaining - performance.now(),
        context.policyFreshnessRemainingMs?.() ?? Infinity,
      ),
    },
    signal: AbortSignal.any([signal, controller.signal]),
    dispose: () => clearTimeout(timer),
  };
}

/** Bind the release and response key before asking the owner to authorize a batch. */
export async function executeServiceCall<T extends ServiceCall>(
  session: ConnectedTvcRuntime,
  call: T,
  callerSignal: AbortSignal,
): Promise<ServiceCallResult<T>> {
  callerSignal.throwIfAborted();
  const approval = call.type === "Decrypt" ? ownerApprovalScope(session, callerSignal) : undefined;
  const context = approval?.context ?? session;
  const signal = approval?.signal ?? callerSignal;
  const { info } = context;
  let responseSecret: Uint8Array | undefined;
  try {
    if (approval && (context.requirePublishedPolicy || context.requireCurrentCheckpoint)) {
      await requireOperationPolicy(context, "ServiceDecrypt", signal);
    }
    requireCurrentReleasePolicy(context, context.nowMs());
    responseSecret = p256.utils.randomPrivateKey();
    const { owner, operation } = call.type === "Decrypt"
      ? {
          owner: call.owner,
          operation: {
            type: "Decrypt" as const,
            signer: call.owner.address,
            expires_at_ms: (context.releasePolicyExpiresAtMs + 1n).toString(),
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
      const publicKey = Uint8Array.from(addressEncoder.encode(address));
      const message = decryptMessage(publicKey, info.network, requestDigest);
      requireCurrentReleasePolicy(context, context.nowMs());
      signal.throwIfAborted();
      const [signatures] = await awaitWithSignal(
        owner.signMessages([createSignableMessage(message.slice())], { abortSignal: signal }), signal,
      );
      requireCurrentReleasePolicy(context, context.nowMs());
      const proposed = signatures?.[address];
      if (!(proposed instanceof Uint8Array) || proposed.length !== ED25519_SIGNATURE_BYTES) {
        throw new DecryptionServiceError("InvalidSignature");
      }
      const signature = new Uint8Array(proposed);
      if (!verifiesOwnerSignature(signature, message, publicKey)) {
        throw new DecryptionServiceError("InvalidSignature");
      }
      request = { ...request, operation: { ...operation, signature: encodeLowerHex(signature) } };
    }

    const plaintext = await sealedExchange(context, {
      request,
      requestDigest,
      responseSecret,
      operation: OPERATION_KINDS[call.type],
    }, signal);
    let result: ServiceResult;
    try {
      result = parseStrictJson<ServiceResult>(plaintext, RESULT_KEYS[call.type]);
    } catch (error) {
      if (error instanceof DecryptionServiceError) throw new AuthenticatedOperationError(error.code);
      throw error;
    }
    if (result.type !== call.type) throw new AuthenticatedOperationError("ReleaseBindingMismatch");
    signal.throwIfAborted();
    requireCurrentReleasePolicy(context, context.nowMs());
    return result as ServiceCallResult<T>;
  } finally {
    responseSecret?.fill(0);
    approval?.dispose();
  }
}
