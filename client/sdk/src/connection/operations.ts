import { parseQosP256Public, qosDecrypt, qosEncrypt } from "../crypto/qos.js";
import { verifyP256Message } from "../crypto/p256.js";
import { SERVICE_PROOF_TYPE } from "../wire/decryption.js";
import { resultDigest } from "../wire/digest.js";
import { DecryptionServiceError } from "../wire/error.js";
import { bytesEqual, encodeLowerHex, requireHex } from "../wire/hex.js";
import { canonicalizeJsonValue, isRfc8785 } from "../wire/jcs.js";
import { assertExactObjectKeys, parseStrictJson } from "../wire/json.js";
import { API_VERSION, QOS_ENVELOPE_OVERHEAD, QOS_P256_PUBLIC_LEN,
  RAW_P256_SIGNATURE_LEN, SHA256_LEN, TVC_APP_PROOF_KEYS, TVC_APP_PROOF_SCHEME,
} from "../wire/constants.js";
import type { OperationKind, ServiceInfo } from "../wire/types.js";
import type { TurnkeyAppProofWire } from "../attestation/turnkey.js";
import { sendToEnclave, type EncryptedRequestWire } from "./backend.js";
import type { ConnectedTvcRuntime } from "./connect.js";
import { awaitWithSignal } from "./request.js";

const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });
const ENCRYPTED_RESPONSE_KEYS = [
  "version",
  "request_id",
  "encrypted_result",
  "tvc_app_proof",
] as const;
/** Room for the JSON envelope and App Proof around the hex ciphertext. */
const RESPONSE_ENVELOPE_SLACK = 65_536n;

const OPERATION_PROOF_KEYS = [
  "type",
  "version",
  "request_id",
  "request_digest",
  "result_digest",
  "operation",
] as const;

type EncryptedResponse = {
  version: number;
  request_id: string;
  encrypted_result: string;
  tvc_app_proof: {
    scheme: string;
    public_key: string;
    proof_payload: string;
    signature: string;
  };
};

type OperationProofPayload = {
  type: string;
  version: number;
  request_id: string;
  request_digest: string;
  result_digest: string;
  operation: OperationKind;
};

export function requireCurrentReleasePolicy(
  window: {
    readonly releasePolicyValidFromMs: bigint;
    readonly releasePolicyExpiresAtMs: bigint;
  },
  nowMs: bigint,
): void {
  if (nowMs < window.releasePolicyValidFromMs || nowMs > window.releasePolicyExpiresAtMs) {
    throw new DecryptionServiceError("ExpiredRequest");
  }
}

/** One request, complete and signed, and what its answer must prove. */
export type Exchange = {
  readonly request: Readonly<{ request_id: string }>;
  readonly requestDigest: Uint8Array;
  /** The secret half of the request's `client_response_public_key`. */
  readonly responseSecret: Uint8Array;
  readonly operation: OperationKind;
};

function encryptedRequest(
  info: ServiceInfo,
  ciphertext: string,
): EncryptedRequestWire {
  return {
    version: API_VERSION,
    quorum_key_id: info.quorum_key_id,
    quorum_key_epoch: info.quorum_key_epoch,
    ciphertext,
  };
}

/** The size of the request the enclave receives, including anything the backend adds. */
function enclaveRequestBytes(request: EncryptedRequestWire): number {
  return te.encode(canonicalizeJsonValue(request)).length;
}

/** The advertised request ceiling covers the entire UTF-8 HTTP body. */
function checkRequestSize(info: ServiceInfo, bytes: number): void {
  if (BigInt(bytes) > BigInt(info.max_encrypted_request_bytes)) {
    throw new DecryptionServiceError("RequestTooLarge");
  }
}

/**
 * Refuses a request too large to send before anyone signs it, so a caller can
 * split the batch. `signed` is the request with its signature at full width.
 */
export function checkSignedRequestSize(
  context: ConnectedTvcRuntime,
  signed: object,
): void {
  const ciphertextBytes =
    te.encode(canonicalizeJsonValue(signed)).length + QOS_ENVELOPE_OVERHEAD;
  checkRequestSize(
    context.info,
    enclaveRequestBytes(encryptedRequest(context.info, "")) + 2 * ciphertextBytes,
  );
}

function asAppProof(proof: EncryptedResponse["tvc_app_proof"]): TurnkeyAppProofWire {
  return {
    scheme: TVC_APP_PROOF_SCHEME,
    publicKey: proof.public_key,
    proofPayload: proof.proof_payload,
    signature: proof.signature,
  };
}

async function verifyOperationProof(
  context: ConnectedTvcRuntime,
  exchange: Exchange,
  response: EncryptedResponse,
  encryptedResult: Uint8Array,
  signal?: AbortSignal,
): Promise<void> {
  assertExactObjectKeys(response.tvc_app_proof, TVC_APP_PROOF_KEYS, "InvalidCanonicalJson");
  const proof = response.tvc_app_proof;
  if (proof.scheme !== TVC_APP_PROOF_SCHEME || !isRfc8785(proof.proof_payload)) {
    throw new DecryptionServiceError("TurnkeyEvidenceInvalid");
  }
  const proofPublic = parseQosP256Public(requireHex(proof.public_key, QOS_P256_PUBLIC_LEN));
  verifyP256Message(
    proofPublic.signing,
    te.encode(proof.proof_payload),
    requireHex(proof.signature, RAW_P256_SIGNATURE_LEN),
  );
  await awaitWithSignal(
    context.trustVerifier.verifyOperationAppProof(asAppProof(proof), signal),
    signal,
  );
  const payload = parseStrictJson<OperationProofPayload>(
    proof.proof_payload,
    OPERATION_PROOF_KEYS,
  );
  if (
    payload.type !== SERVICE_PROOF_TYPE ||
    payload.version !== API_VERSION ||
    payload.request_id !== exchange.request.request_id ||
    payload.request_digest !== encodeLowerHex(exchange.requestDigest) ||
    payload.result_digest !== encodeLowerHex(resultDigest(encryptedResult)) ||
    payload.operation !== exchange.operation
  ) {
    throw new DecryptionServiceError("ReleaseBindingMismatch");
  }
}

/**
 * Encrypts the request to the Quorum key, sends it, and opens the answer once
 * its App Proof names this request and its result. The caller owns the response secret.
 */
export async function sealedExchange(
  context: ConnectedTvcRuntime,
  exchange: Exchange,
  signal?: AbortSignal,
): Promise<string> {
  signal?.throwIfAborted();
  const quorum = parseQosP256Public(
    requireHex(context.info.quorum_public_key, QOS_P256_PUBLIC_LEN),
  );
  const ciphertext = await qosEncrypt(
    quorum.encryption,
    te.encode(canonicalizeJsonValue(exchange.request)),
  );
  const encrypted = encryptedRequest(context.info, encodeLowerHex(ciphertext));
  checkRequestSize(context.info, enclaveRequestBytes(encrypted));
  // The ciphertext is hex, so it cannot exceed twice the byte ceiling;
  // RESPONSE_ENVELOPE_SLACK covers the surrounding JSON and App Proof.
  const maxResponseBytes = BigInt(context.info.max_encrypted_response_bytes);
  const responseText = await sendToEnclave(
    context.backend.endpoint, encrypted, context.transport,
    maxResponseBytes * 2n + RESPONSE_ENVELOPE_SLACK, signal,
  );
  const response = parseStrictJson<EncryptedResponse>(responseText, ENCRYPTED_RESPONSE_KEYS);
  if (
    response.version !== API_VERSION ||
    !bytesEqual(
      requireHex(response.request_id, SHA256_LEN),
      requireHex(exchange.request.request_id, SHA256_LEN),
    )
  ) {
    throw new DecryptionServiceError("ReleaseBindingMismatch");
  }
  const encryptedResult = requireHex(response.encrypted_result);
  if (BigInt(encryptedResult.length) > maxResponseBytes) {
    throw new DecryptionServiceError("ResponseTooLarge");
  }
  await verifyOperationProof(context, exchange, response, encryptedResult, signal);
  let plaintext: string;
  try {
    plaintext = td.decode(qosDecrypt(exchange.responseSecret, encryptedResult));
  } catch {
    throw new DecryptionServiceError("InvalidEncryptedEnvelope");
  }
  if (!isRfc8785(plaintext)) throw new DecryptionServiceError("InvalidCanonicalJson");
  return plaintext;
}
