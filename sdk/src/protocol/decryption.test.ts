import { describe, expect, it } from "vitest";

import { encodeLowerHex } from "./hex.js";
import { decryptMessage, serviceRequestDigest, type ServiceRequest } from "./decryption.js";

// The same request and vectors as `protocol/tests/unit/decryption_request_binding.rs`.
const request: ServiceRequest = {
  version: 2,
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
const DIGEST = "57de6984916cb0b0f12b15535c704853c01136d99ffcca29547bc441b944a5fb";
const MESSAGE =
  "ff736f6c616e61206f6666636861696e00e80ca057c8ae40aaee353f7ee35a972bb911496758a0e5f62f8292f066ab94f8000107070707070707070707070707070707070707070707070707070707070707076b00545350502f64656372797074696f6e2d736572766963652f646563727970742f76322f6d61696e6e65742f30393039303930393039303930393039303930393039303930393039303930393039303930393039303930393039303930393039303930393039303930393039";

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
});
