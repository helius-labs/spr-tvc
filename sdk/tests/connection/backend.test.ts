import { describe, expect, it } from "vitest";
import { sendToEnclave } from "../../src/connection/backend.js";

const endpoint = new URL("https://example.invalid");
const request = { version: 1, quorum_key_id: "quorum", quorum_key_epoch: "1", ciphertext: "00" };

describe("direct operations", () => {
  it.each([[400, "OperationRejected"], [429, "OperationRejected"], [503, "OperationUnavailable"]])(
    "maps HTTP %s to %s",
    async (status, code) => {
      await expect(sendToEnclave(
        endpoint, request,
        { fetch: async () => new Response(null, { status, headers: { "retry-after": "5" } }) },
        1024n,
      )).rejects.toMatchObject({ code, status, retryAfter: "5" });
    },
  );

  it("preserves a caller cancellation during the replica response window", async () => {
    const controller = new AbortController();
    const reason = new Error("wallet cancelled");
    const pending = sendToEnclave(endpoint, request, { fetch: async () => new Promise(() => {}) },
      1024n, controller.signal, 12_000);
    const cancelled = expect(pending).rejects.toBe(reason);
    controller.abort(reason);
    await cancelled;
  });

  it("reports a broken native response stream as an unavailable replica", async () => {
    const body = new ReadableStream({ start(controller) { controller.error(new TypeError("connection closed")); } });
    await expect(sendToEnclave(endpoint, request, { fetch: async () => new Response(body) },
      1024n, undefined, 12_000)).rejects.toMatchObject({ code: "EndpointUnavailable" });
  });
});
