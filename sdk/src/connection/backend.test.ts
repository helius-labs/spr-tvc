import { describe, expect, it } from "vitest";
import { sendToEnclave } from "./backend.js";

describe("direct operations", () => {
  it.each([[400, "OperationRejected"], [429, "OperationRejected"], [503, "OperationUnavailable"]])(
    "maps HTTP %s to %s",
    async (status, code) => {
      await expect(sendToEnclave(
        new URL("https://example.invalid"),
        { version: 1, quorum_key_id: "quorum", quorum_key_epoch: "1", ciphertext: "00" },
        { fetch: async () => new Response(null, { status, headers: { "retry-after": "5" } }) },
        1024n,
      )).rejects.toMatchObject({ code, status, retryAfter: "5" });
    },
  );
});
