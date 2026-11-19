import { p256 } from "@noble/curves/p256";
import { createSignableMessage, getAddressEncoder, type MessagePartialSigner } from "@solana/kit";

import { sendDecryptionOperation } from "../client/backend.js";
import type { ConnectedTvcRuntime } from "../client/connection.js";
import {
  checkSignedRequestSize,
  requireCurrentReleasePolicy,
  sealedExchange,
} from "../client/operation-executor.js";
import { API_VERSION } from "../protocol/constants.js";
import { SprEmbeddedWalletError } from "../protocol/error.js";
import { encodeLowerHex } from "../protocol/hex.js";
import { parseStrictJson } from "../protocol/json.js";
import type { DecryptItem } from "../protocol/types.js";
import {
  SERVICE_PROOF_TYPE,
  decryptMessage,
  serviceRequestDigest,
  type ServiceOperation,
  type ServiceRequest,
  type ServiceResult,
} from "./protocol.js";

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
    checkSignedRequestSize(context, request, {});
    if (owner) {
      const address = operation.signer;
      const message = decryptMessage(
        new Uint8Array(addressEncoder.encode(address)),
        info.network,
        requestDigest,
      );
      const [signatures] = await owner.signMessages([createSignableMessage(message)]);
      const signature = signatures?.[address];
      if (signature?.length !== ED25519_SIGNATURE_BYTES) {
        throw new SprEmbeddedWalletError("InvalidSignature");
      }
      request = { ...request, operation: { ...operation, signature: encodeLowerHex(signature) } };
    }

    const { plaintext } = await sealedExchange(context, {
      request,
      requestDigest,
      responseSecret,
      operation: OPERATION_KINDS[call.type],
      proofType: SERVICE_PROOF_TYPE,
      grant: {},
      send: (encrypted, maxAnswerBytes) =>
        sendDecryptionOperation(context.backend, encrypted, context.transport, maxAnswerBytes, signal),
    }, signal);
    const result = parseStrictJson<ServiceResult>(plaintext, RESULT_KEYS[call.type]);
    if (result.type !== call.type) throw new SprEmbeddedWalletError("ReleaseBindingMismatch");
    return result as ServiceCallResult<T>;
  } finally {
    responseSecret.fill(0);
  }
}
