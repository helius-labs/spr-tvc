import { awaitWithSignal } from "./request.js";
import { DecryptionServiceError } from "../protocol/error.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import type {
  TurnkeyAppProofWire,
  TurnkeyBootProofWire,
} from "../verify/internal/turnkey-proof-seam.js";
import { endpointUrl, fetchWithSignal, httpError, readBoundedText } from "./http.js";
import type { DecryptionServiceTransport } from "./transport.js";

export type ResolveBootProofInput = {
  readonly appProof: TurnkeyAppProofWire;
  readonly bootProofLookupKey: string;
  readonly signal?: AbortSignal;
};

export type BootProofResolver = (input: ResolveBootProofInput) => Promise<TurnkeyBootProofWire>;

export type EnclaveBackend = {
  readonly endpoint: URL;
  readonly resolveBootProof?: BootProofResolver;
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

export async function fetchSession(
  backend: EnclaveBackend,
  pingBody: string,
  transport: DecryptionServiceTransport,
  signal?: AbortSignal,
): Promise<{ infoText: string; pingText: string }> {
  const { endpoint } = backend;
  const info = await fetchWithSignal(transport, endpointUrl(endpoint, "/v1/info"), undefined, signal);
  const infoText = await readAnswer(info, "DiscoveryUntrusted", MAX_DISCOVERY_RESPONSE_BYTES, signal);
  return { infoText, pingText: await fetchPing(endpoint, pingBody, transport, signal) };
}

/** The Boot Proof of the replica that signed `appProof`, for an answer that carried none. */
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
