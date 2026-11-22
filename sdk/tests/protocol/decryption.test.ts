import { describe, expect, it } from "vitest";

import { encodeLowerHex } from "../../src/protocol/hex.js";
import { decryptMessage, serviceRequestDigest, type ServiceRequest } from "../../src/protocol/decryption.js";

// The same request and vectors as `protocol/tests/unit/decryption_request_binding.rs`.
const request: ServiceRequest = {
  version: 1,
  request_id: "01".repeat(32),
  target_release_id: "release",
  target_manifest_digest: "02".repeat(32),
  target_executable_digest: "03".repeat(32),
  quorum_key_id: "quorum",
  quorum_key_epoch: "1",
  client_response_public_key: "04".repeat(65),
  operation: {
    type: "Decrypt",
    signer: "11111111111111111111111111111111",
    expires_at_ms: "1795290720000",
    signature: "00".repeat(64),
    items: [{
      ciphertext: "010203",
      ephemeral_viewing_public_key: "04".repeat(33),
      salt: "00".repeat(16),
      slot_index: "0",
      label: "Transfer",
    }],
  },
};
const DIGEST = "c7756715907ee016a5a564dc38aefb73a50f51db6d5bb568090b7c5871ae99b1";
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

  it("binds the release ID and rejects invalid Unicode before hashing", () => {
    expect(encodeLowerHex(serviceRequestDigest({ ...request, target_release_id: "release-2" }))).not.toBe(DIGEST);
    expect(() => serviceRequestDigest({ ...request, target_release_id: "\ud800" })).toThrow("InvalidCanonicalJson");
  });
});
