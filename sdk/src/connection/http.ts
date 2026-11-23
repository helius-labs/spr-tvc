import { awaitWithSignal } from "./request.js";
import { DecryptionServiceError, DecryptionServiceHttpError } from "../protocol/error.js";

/** Fetch implementation used for enclave HTTP requests. */
export type DecryptionServiceTransport = {
  fetch(input: URL, init?: RequestInit): Promise<Response>;
};

export function createDefaultTransport(): DecryptionServiceTransport {
  return { fetch: (input, init) => fetch(input, init) };
}

const td = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

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
export async function readBoundedBytes(
  response: Response,
  maxBytes: bigint,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  signal?.throwIfAborted();
  if (maxBytes <= 0n || maxBytes > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new DecryptionServiceError("ResponseTooLarge");
  }
  const limit = Number(maxBytes);
  if (!response.body) return new Uint8Array(0);
  const reader = response.body.getReader();
  let body = new Uint8Array(0);
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await awaitWithSignal(reader.read(), signal);
      if (done) break;
      const end = total + value.length;
      if (end > limit) throw new DecryptionServiceError("ResponseTooLarge");
      if (end > body.length) {
        const grown = new Uint8Array(Math.min(limit, Math.max(end, 2 * body.length)));
        grown.set(body);
        body = grown;
      }
      body.set(value, total);
      total = end;
    }
  } finally {
    // A custom stream may never settle its cancellation promise.
    void reader.cancel().catch(() => undefined);
  }
  return body.subarray(0, total);
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
