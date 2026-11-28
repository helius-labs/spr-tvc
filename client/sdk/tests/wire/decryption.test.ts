// Covers INV-04 (decrypt digest & Solana off-chain message parity) and INV-09 (view-grant digest & 30-minute window).

import { describe, expect, it } from "vitest";

import { encodeLowerHex } from "../../src/wire/hex.js";
import {
  acceptViewGrantWindow,
  decryptMessage,
  MAX_VIEW_GRANT_MS,
  serviceRequestDigest,
  type ServiceRequest,
} from "../../src/wire/decryption.js";

// The same request and vectors as `wire/tests/unit/decryption_request_binding.rs`.
const request: ServiceRequest = {
  version: 1,
  request_id: "01".repeat(32),
  quorum_key_id: "quorum",
  quorum_key_epoch: "1",
  client_response_public_key: "04".repeat(65),
  operation: {
    type: "Decrypt",
    signer: "11111111111111111111111111111111",
    signature: "00".repeat(64),
    items: [{
      ciphertext: "010203",
      ephemeral_viewing_public_key: "04".repeat(33),
      salt: "00".repeat(16),
      slot_index: "0",
      label: "Transfer",
      kdf: "HkdfSha256Ctr",
    }],
  },
};
const DIGEST = "fa1fd1749eed328af9f1192dd515323ad3af23a9768a7b3ebc92f05b16a92a5b";
const MESSAGE =
  "ff736f6c616e61206f6666636861696e005be1ef179167714826436f2f8f69579bd2bd3f7b3ad3cf18e4a0b6a1a0700e27000107070707070707070707070707070707070707070707070707070707070707076b00545350502f64656372797074696f6e2d736572766963652f646563727970742f76312f6d61696e6e65742f30393039303930393039303930393039303930393039303930393039303930393039303930393039303930393039303930393039303930393039303930393039";

describe("the decryption service's request", () => {
  it("has the digest the enclave computes, whatever its signature", () => {
    expect(encodeLowerHex(serviceRequestDigest(request))).toBe(DIGEST);
    const signed = { ...request, operation: { ...request.operation, signature: "01".repeat(64) } };
    expect(encodeLowerHex(serviceRequestDigest(signed))).toBe(DIGEST);
  });

  it("is authorized by the off-chain message the enclave rebuilds", () => {
    const message = decryptMessage(new Uint8Array(32).fill(7), "mainnet", new Uint8Array(32).fill(9));
    expect(encodeLowerHex(message)).toBe(MESSAGE);
  });

  it("covers a view grant and keeps the owner's signature inside it", () => {
    const grant = {
      owner: "owner",
      grantee: "grantee",
      network: "devnet" as const,
      quorum_key_id: "quorum",
      quorum_key_epoch: "1",
      not_before_ms: "1000",
      expiry_ms: "2000",
      signature: "ab".repeat(64),
    };
    const withGrant = { ...request, operation: { ...request.operation, grant } };
    expect(encodeLowerHex(serviceRequestDigest(withGrant))).not.toBe(DIGEST);
    const resigned = { ...withGrant, operation: { ...withGrant.operation, grant: { ...grant, signature: "cd".repeat(64) } } };
    expect(encodeLowerHex(serviceRequestDigest(resigned))).not.toBe(encodeLowerHex(serviceRequestDigest(withGrant)));
  });

  it("accepts a half-open window of at most 30 minutes", () => {
    const now = 1_000_000n;
    expect(() => acceptViewGrantWindow(now, now + MAX_VIEW_GRANT_MS, now)).not.toThrow();
    expect(() => acceptViewGrantWindow(now, now + MAX_VIEW_GRANT_MS, now + MAX_VIEW_GRANT_MS)).toThrow(/ExpiredRequest/);
    expect(() => acceptViewGrantWindow(now, now + MAX_VIEW_GRANT_MS + 1n, now)).toThrow(/ExpiredRequest/);
  });

  it("binds the Quorum key and rejects invalid Unicode before hashing", () => {
    expect(encodeLowerHex(serviceRequestDigest({ ...request, quorum_key_id: "quorum-2" }))).not.toBe(DIGEST);
    expect(() => serviceRequestDigest({ ...request, quorum_key_id: "\ud800" })).toThrow("InvalidCanonicalJson");
  });
});
