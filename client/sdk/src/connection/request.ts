import { DEFAULT_REQUEST_TIMEOUT_MS, MAX_SET_TIMEOUT_MS } from "../wire/constants.js";
import { DecryptionServiceError } from "../wire/error.js";

/** Applies to the whole SDK call, including verification and any decrypt batches. */
export interface DecryptionServiceRequestOptions {
  readonly signal?: AbortSignal;
  /** Total time allowed in milliseconds. Defaults to the client setting, or two minutes. */
  readonly timeoutMs?: number;
}

export function requestScope(
  options: DecryptionServiceRequestOptions = {},
  defaultTimeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
) {
  const timeoutMs = options.timeoutMs ?? defaultTimeoutMs;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_SET_TIMEOUT_MS) {
    throw new DecryptionServiceError("InvalidRequestTimeout");
  }
  const controller = new AbortController();
  const signal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal;
  const timer = setTimeout(() => controller.abort(new DOMException("TVC request timed out", "TimeoutError")), timeoutMs);
  return { signal, dispose: () => clearTimeout(timer) };
}

/** Only race work whose late result cannot authorize, publish a connection, or write storage. */
export async function awaitWithSignal<T>(work: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return work;
  let abort!: () => void;
  const cancelled = new Promise<never>((_resolve, reject) => {
    abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
  });
  try {
    const result = await Promise.race([work, cancelled]);
    signal.throwIfAborted();
    return result;
  } finally { signal.removeEventListener("abort", abort); }
}
