import { p256 } from "@noble/curves/p256";
import { createSignableMessage, getAddressEncoder, type MessagePartialSigner } from "@solana/kit";

import type { ConnectedTvcRuntime } from "../connection/connect.js";
import {
  checkSignedRequestSize,
  requireCurrentReleasePolicy,
  sealedExchange,
} from "../connection/operations.js";
import { awaitWithSignal } from "../connection/request.js";
import { API_VERSION } from "../wire/constants.js";
import { DecryptionServiceError } from "../wire/error.js";
import { encodeLowerHex } from "../wire/hex.js";
import { parseStrictJson } from "../wire/json.js";
import type { DecryptItem } from "../wire/types.js";
import { decodeDecimalU64 } from "../wire/decimal.js";
import {
  acceptViewGrantWindow,
  decryptMessage,
  serviceRequestDigest,
  type ServiceOperation,
  type ServiceRequest,
  type ServiceResult,
  type ViewGrant,
} from "../wire/decryption.js";

const ED25519_SIGNATURE_BYTES = 64;
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
  readonly grant?: ViewGrant;
};

export type ServiceCall = Extract<ServiceOperation, { type: "PublicKeys" }> | DecryptCall;
export type ServiceCallResult<T extends ServiceCall> = Extract<ServiceResult, { type: T["type"] }>;

/** Bind the release and response key before asking the owner to authorize a batch. */
export async function executeServiceCall<T extends ServiceCall>(
  context: ConnectedTvcRuntime,
  call: T,
  signal: AbortSignal,
): Promise<ServiceCallResult<T>> {
  const { info } = context;
  signal.throwIfAborted();
  requireCurrentReleasePolicy(context, context.nowMs());
  const responseSecret = p256.utils.randomPrivateKey();
  try {
    if (call.type === "Decrypt" && call.grant) {
      if (call.grant.grantee !== call.owner.address) {
        throw new DecryptionServiceError("InvalidSignature");
      }
      acceptViewGrantWindow(
        decodeDecimalU64(call.grant.not_before_ms),
        decodeDecimalU64(call.grant.expiry_ms),
        context.nowMs(),
      );
    }
    const { owner, operation } = call.type === "Decrypt"
      ? {
          owner: call.owner,
          operation: {
            type: "Decrypt" as const,
            signer: call.owner.address,
            signature: EMPTY_SIGNATURE,
            items: call.items,
            ...(call.grant === undefined ? {} : { grant: call.grant }),
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
      signal.throwIfAborted();
      const [signatures] = await awaitWithSignal(
        owner.signMessages([createSignableMessage(message)], { abortSignal: signal }),
        signal,
      );
      const signature = signatures?.[address];
      if (signature?.length !== ED25519_SIGNATURE_BYTES) {
        throw new DecryptionServiceError("InvalidSignature");
      }
      request = { ...request, operation: { ...operation, signature: encodeLowerHex(signature) } };
    }

    requireCurrentReleasePolicy(context, context.nowMs());
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
