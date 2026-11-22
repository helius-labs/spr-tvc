export class DecryptionServiceError extends Error {
  readonly code: string;

  /**
   * `code` is the stable protocol identifier callers compare against; `detail`
   * is optional human-readable context, which may include untrusted text and
   * therefore never becomes part of `code`.
   */
  constructor(code: string, detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = "DecryptionServiceError";
    this.code = code;
  }
}

/** The reply was authenticated for this request and then failed validation. */
export class AuthenticatedOperationError extends DecryptionServiceError {}

/** HTTP failures retain rate-limit information without returning an untrusted response body. */
export class DecryptionServiceHttpError extends DecryptionServiceError {
  readonly status: number;
  readonly retryAfter: string | null;

  constructor(code: string, status: number, retryAfter: string | null) {
    super(code, `HTTP ${status}`);
    this.name = "DecryptionServiceHttpError";
    this.status = status;
    this.retryAfter = retryAfter;
  }
}
