import { address, signatureBytes } from "@solana/kit";
import { p256 } from "@noble/curves/p256";
import { expect, it, vi } from "vitest";

import type { ConnectedTvcRuntime } from "../connection/connect.js";
import { qosDecrypt } from "../crypto/qos.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type { ServiceInfo } from "../protocol/types.js";
import { executeServiceCall } from "./exchange.js";
import { decryptionServiceFromSession } from "./decryption.js";
import type { ServiceRequest } from "../protocol/decryption.js";

function fixture() {
  const quorum = new Uint8Array(32).fill(1);
  const publicKey = encodeLowerHex(p256.getPublicKey(quorum, false));
  const info = {
    version: 1, network: "devnet", security_domain_id: "00".repeat(32),
    release_id: "release", manifest_digest: "11".repeat(32), executable_digest: "22".repeat(32),
    quorum_public_key: publicKey + publicKey, quorum_key_id: "quorum", quorum_key_epoch: "1",
    supported_operations: ["ServicePublicKeys", "ServiceDecrypt"],
    max_encrypted_request_bytes: "262144", max_encrypted_response_bytes: "262144", proof_type: "",
  } satisfies ServiceInfo;
  const fetch = vi.fn(async (_url: unknown, _init?: RequestInit) => new Response("", { status: 503 }));
  const context: ConnectedTvcRuntime = {
    backend: { endpoint: new URL("https://example.invalid") },
    info, transport: { fetch },
    releasePolicyValidFromMs: 0n, releasePolicyExpiresAtMs: 9999999n, nowMs: () => 1000n,
    trustVerifier: { verifyOperationAppProof: async () => {} },
  };
  return { context, fetch, quorum, info };
}

it("asks for an address's keys from the release it verified", async () => {
  const { context, fetch, quorum, info } = fixture();
  const forget = vi.fn();
  const service = decryptionServiceFromSession({ context: async () => context, forget, reset: vi.fn() });
  const owner = address("11111111111111111111111111111111");

  await expect(service.address(owner)).rejects.toMatchObject({ code: "OperationUnavailable" });

  expect(String(fetch.mock.calls[0]?.[0])).toBe("https://example.invalid/v1/operations");
  const body = JSON.parse(fetch.mock.calls[0]?.[1]?.body as string) as { ciphertext: string };
  expect(Object.keys(body).sort()).toEqual(["ciphertext", "quorum_key_epoch", "quorum_key_id", "version"]);
  const request = JSON.parse(new TextDecoder().decode(qosDecrypt(quorum, decodeLowerHex(body.ciphertext)))) as ServiceRequest;
  expect(request).toMatchObject({
    target_release_id: "release",
    target_manifest_digest: info.manifest_digest,
    target_executable_digest: info.executable_digest,
    operation: { type: "PublicKeys", address: owner },
  });
  // A failed exchange may mean the release moved on.
  expect(forget).toHaveBeenCalledWith(context);
});


it("checks the serialized request ceiling before asking for a signature or sending bytes", async () => {
  const { context, fetch } = fixture();
  const signMessages = vi.fn();
  await expect(executeServiceCall({
    ...context, info: { ...context.info, max_encrypted_request_bytes: "512" },
  }, {
    type: "Decrypt",
    owner: { address: address("11111111111111111111111111111111"), signMessages },
    items: [{
      ciphertext: "aa".repeat(512), ephemeral_viewing_public_key: "04".repeat(33),
      slot_index: "0", salt: "00".repeat(16), label: "Transfer",
    }],
  }, new AbortController().signal)).rejects.toMatchObject({ code: "RequestTooLarge" });
  expect(signMessages).not.toHaveBeenCalled();
  expect(fetch).not.toHaveBeenCalled();
});


it("stops awaiting a cancelled owner approval and wipes the response key", async () => {
  const { context, fetch } = fixture();
  const scope = new AbortController();
  const responseSecret = new Uint8Array(32).fill(9);
  const random = vi.spyOn(p256.utils, "randomPrivateKey").mockReturnValueOnce(responseSecret);
  const owner = {
    address: address("11111111111111111111111111111111"),
    signMessages: vi.fn(() => new Promise<never>(() => {})),
  };
  try {
    const pending = executeServiceCall(context, { type: "Decrypt", owner, items: [] }, scope.signal);
    const rejected = expect(pending).rejects.toThrow("owner cancelled");
    expect(owner.signMessages).toHaveBeenCalledWith(expect.any(Array), { abortSignal: scope.signal });
    scope.abort(new Error("owner cancelled"));
    await rejected;
    expect(fetch).not.toHaveBeenCalled();
    expect(responseSecret).toEqual(new Uint8Array(32));
  } finally {
    random.mockRestore();
  }
});

it("refuses to send a request signed after the release expires", async () => {
  const { context, fetch } = fixture();
  let now = 1000n;
  const ownerAddress = address("11111111111111111111111111111111");
  const owner = {
    address: ownerAddress,
    signMessages: vi.fn(async () => {
      now = context.releasePolicyExpiresAtMs + 1n;
      return [{ [ownerAddress]: signatureBytes(new Uint8Array(64).fill(1)) }];
    }),
  };
  await expect(executeServiceCall({ ...context, nowMs: () => now }, {
    type: "Decrypt", owner, items: [],
  }, new AbortController().signal)).rejects.toMatchObject({ code: "ExpiredRequest" });
  expect(owner.signMessages).toHaveBeenCalledOnce();
  expect(fetch).not.toHaveBeenCalled();
});
