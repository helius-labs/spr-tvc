import { p256 } from "@noble/curves/p256";
import { expect, it, vi } from "vitest";

import type { ConnectedTvcRuntime } from "../connection/connect.js";
import { qosDecrypt } from "../crypto/qos.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type { ServiceInfo } from "../protocol/types.js";
import { decryptionServiceFromSession } from "./decryption.js";
import type { ServiceRequest } from "../protocol/decryption.js";

it("asks for an address's keys from the release it verified, with no grant", async () => {
  const quorum = new Uint8Array(32).fill(1);
  const publicKey = encodeLowerHex(p256.getPublicKey(quorum, false));
  const info = {
    version: 1, network: "devnet", security_domain_id: "00".repeat(32),
    release_id: "release", manifest_digest: "11".repeat(32), executable_digest: "22".repeat(32),
    quorum_public_key: publicKey + publicKey, quorum_key_id: "quorum", quorum_key_epoch: "1",
    ephemeral_public_key: "", supported_operations: ["ServicePublicKeys", "ServiceDecrypt"],
    max_encrypted_request_bytes: "262144", max_encrypted_response_bytes: "262144", proof_type: "",
  } satisfies ServiceInfo;
  const fetch = vi.fn(async (_url: unknown, _init?: RequestInit) => new Response("", { status: 503 }));
  const context: ConnectedTvcRuntime = {
    backend: { endpoint: new URL("https://example.invalid") },
    info, transport: { fetch },
    releasePolicyValidFromMs: 0n, releasePolicyExpiresAtMs: 9999999n, nowMs: () => 1000n,
    trustVerifier: { verifyOperationAppProof: async () => {} },
  };
  const forget = vi.fn();
  const service = decryptionServiceFromSession({ context: async () => context, forget, reset: vi.fn() });
  const owner = "11111111111111111111111111111111" as never;

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
