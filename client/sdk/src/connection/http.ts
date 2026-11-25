import { awaitWithSignal } from "./request.js";
import { DecryptionServiceError, DecryptionServiceHttpError } from "../wire/error.js";

/** Fetch implementation used for enclave HTTP requests. */
export type DecryptionServiceTransport = {
  fetch(input: URL, init?: RequestInit): Promise<Response>;
};

export function createDefaultTransport(): DecryptionServiceTransport {
  return { fetch: (input, init) => fetch(input, init) };
}

const td = new TextDecoder("utf-8", { fatal: true });

export function endpointUrl(endpoint: URL, path: string): URL {
  const base = new URL(endpoint);
  if (!base.pathname.endsWith("/")) base.pathname += "/";
  return new URL(path.replace(/^\/+/, ""), base);
}

/**
 * Reads an untrusted response body without first buffering an attacker-chosen
 * amount of data. TVC responses are canonical JSON, so malformed UTF-8 is a
 * protocol error rather than text that may be repaired with U+FFFD.
 */
export async function readBoundedText(response: Response, maxBytes: bigint, signal?: AbortSignal): Promise<string> {
  const body = await readBoundedBytes(response, maxBytes, signal);
  try {
    return td.decode(body);
  } catch {
    throw new DecryptionServiceError("InvalidCanonicalJson");
  }
}

/** Reads an untrusted response body as bytes, refusing more than `maxBytes`. */
async function readBoundedBytes(
  response: Response,
  maxBytes: bigint,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  signal?.throwIfAborted();
  if (maxBytes <= 0n || maxBytes > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new DecryptionServiceError("ResponseTooLarge");
  }
  const limit = Number(maxBytes);
  if (!response.body) {
    const body = new Uint8Array(await awaitWithSignal(response.arrayBuffer(), signal));
    if (body.length > limit) throw new DecryptionServiceError("ResponseTooLarge");
    return body;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await awaitWithSignal(reader.read(), signal);
      if (done) break;
      total += value.length;
      if (total > limit) throw new DecryptionServiceError("ResponseTooLarge");
      chunks.push(value);
    }
  } finally {
    // A custom stream may never settle its cancellation promise.
    void reader.cancel().catch(() => undefined);
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

/** Cancel a late custom-transport response as well as native fetch. */
export async function fetchWithSignal(
  transport: DecryptionServiceTransport, url: URL, init?: RequestInit, signal?: AbortSignal,
): Promise<Response> {
  signal?.throwIfAborted();
  const work = transport.fetch(url, { ...init, ...(signal ? { signal } : {}) });
  try { return await awaitWithSignal(work, signal); }
  catch (error) {
    if (signal?.aborted) void work.then((response) => response.body?.cancel()).catch(() => undefined);
    throw error;
  }
}

export function httpError(response: Response, code: string): DecryptionServiceHttpError {
  void response.body?.cancel().catch(() => undefined);
  return new DecryptionServiceHttpError(code, response.status, response.headers.get("retry-after"));
}
