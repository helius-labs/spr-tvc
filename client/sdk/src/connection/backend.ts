import { awaitWithSignal } from "./request.js";
import { DecryptionServiceError } from "../wire/error.js";
import { canonicalizeJsonValue } from "../wire/jcs.js";
import { parseStrictJson } from "../wire/json.js";
import type {
  TurnkeyAppProofWire,
  TurnkeyBootProofWire,
} from "../attestation/turnkey.js";
import { endpointUrl, fetchWithSignal, httpError, readBoundedText, type DecryptionServiceTransport } from "./http.js";

export type ResolveBootProofInput = {
  readonly appProof: TurnkeyAppProofWire;
  readonly bootProofLookupKey: string;
  readonly signal?: AbortSignal;
};

export type BootProofResolver = (input: ResolveBootProofInput) => Promise<TurnkeyBootProofWire>;

export type EnclaveBackend = {
  readonly endpoint: URL;
  readonly resolveBootProof?: BootProofResolver;
  /** Sent as `x-api-key`. The reply then includes the Boot Proof. */
  readonly apiKey?: string;
};

/** The enclave's request fields around the ciphertext. */
export type EncryptedRequestWire = {
  readonly version: number;
  readonly quorum_key_id: string;
  readonly quorum_key_epoch: string;
  readonly ciphertext: string;
};

const MAX_DISCOVERY_RESPONSE_BYTES = 64n * 1024n;
const MAX_PING_RESPONSE_BYTES = 64n * 1024n;
const MAX_BOOT_PROOF_BYTES = 512n * 1024n;

function postOperation(
  backend: EnclaveBackend,
  route: "operations",
  transport: DecryptionServiceTransport,
  body: string,
  signal?: AbortSignal,
): Promise<Response> {
  const apiKey = backend.apiKey;
  if (apiKey === undefined || !apiKey.trim()) throw new DecryptionServiceError("InvalidServiceConfig");
  return fetchWithSignal(transport, endpointUrl(backend.endpoint, `/v1/decryption/${route}`), {
    method: "POST",
    redirect: "error",
    headers: { "content-type": "application/json", "x-api-key": apiKey },
    body,
  }, signal);
}

function postJson(transport: DecryptionServiceTransport, url: URL, body: string, signal?: AbortSignal): Promise<Response> {
  return fetchWithSignal(transport, url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  }, signal);
}

async function readAnswer(
  response: Response,
  failureCode: string,
  maxBytes: bigint,
  signal?: AbortSignal,
): Promise<string> {
  if (!response.ok) throw httpError(response, failureCode);
  return readBoundedText(response, maxBytes, signal);
}

/** The enclave's answer to `pingBody`, a QOS ping encrypted to its quorum key. */
export async function fetchPing(
  endpoint: URL,
  pingBody: string,
  transport: DecryptionServiceTransport,
  signal?: AbortSignal,
): Promise<string> {
  const ping = await postJson(transport, endpointUrl(endpoint, "/v1/ping"), pingBody, signal);
  return readAnswer(ping, "BootProofUnverified", MAX_PING_RESPONSE_BYTES, signal);
}

export async function fetchDiscovery(
  endpoint: URL,
  transport: DecryptionServiceTransport,
  signal?: AbortSignal,
): Promise<string> {
  const response = await fetchWithSignal(transport, endpointUrl(endpoint, "/v1/info"), undefined, signal);
  return readAnswer(response, "DiscoveryUntrusted", MAX_DISCOVERY_RESPONSE_BYTES, signal);
}

/** Looks up the Boot Proof for the replica that signed `appProof`. */
export function lookupBootProof(
  backend: EnclaveBackend,
  appProof: TurnkeyAppProofWire,
  signal?: AbortSignal,
): Promise<TurnkeyBootProofWire> {
  if (!backend.resolveBootProof) {
    return Promise.reject(new DecryptionServiceError("BootProofUnverified"));
  }
  return awaitWithSignal(backend.resolveBootProof({
    appProof,
    bootProofLookupKey: appProof.publicKey,
    ...(signal ? { signal } : {}),
  }), signal);
}

/** Posts the encrypted request to the enclave and bounds the response. */
export async function sendToEnclave(
  endpoint: URL,
  request: EncryptedRequestWire,
  transport: DecryptionServiceTransport,
  maxAnswerBytes: bigint,
  signal?: AbortSignal,
): Promise<string> {
  const response = await postJson(
    transport, endpointUrl(endpoint, "/v1/operations"), canonicalizeJsonValue(request), signal,
  );
  const code = response.status >= 500 ? "OperationUnavailable" : "OperationRejected";
  return readAnswer(response, code, maxAnswerBytes, signal);
}

/** Posts one operation. With an API key, the answer is the enclave response plus that replica's Boot Proof. */
export async function sendOperation(
  backend: EnclaveBackend,
  request: EncryptedRequestWire,
  transport: DecryptionServiceTransport,
  maxAnswerBytes: bigint,
  signal?: AbortSignal,
): Promise<{ responseText: string; bootProof?: TurnkeyBootProofWire }> {
  if (backend.apiKey === undefined) {
    return { responseText: await sendToEnclave(backend.endpoint, request, transport, maxAnswerBytes, signal) };
  }
  const response = await postOperation(
    backend, "operations", transport, canonicalizeJsonValue(request), signal,
  );
  const code = response.status >= 500 ? "OperationUnavailable" : "OperationRejected";
  const text = await readAnswer(response, code, maxAnswerBytes + MAX_BOOT_PROOF_BYTES, signal);
  const answer = parseStrictJson<{ response: unknown; bootProof: TurnkeyBootProofWire }>(
    text, ["response", "bootProof"],
  );
  const responseText = JSON.stringify(answer.response);
  if (BigInt(new TextEncoder().encode(responseText).length) > maxAnswerBytes) {
    throw new DecryptionServiceError("ResponseTooLarge");
  }
  return { responseText, bootProof: answer.bootProof };
}
