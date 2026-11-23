import { describe, expect, it } from "vitest";

import { encodeLowerHex } from "./hex.js";
import {
  decryptMessage,
  serviceRequestDigest,
  viewGrantDigest,
  viewGrantMessage,
  type ServiceRequest,
  type ViewGrant,
} from "./decryption.js";

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
    derivation: "11111111111111111111111111111111",
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
const DIGEST = "31e11ba9039dd52991f81208b07b332ac9e4d6d2f71f328c03faa5978d5d9cfd";
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

  it("hashes a view grant the way the enclave does, ignoring its signature", () => {
    const grant: ViewGrant = {
      derivation: "11111111111111111111111111111111",
      grantee: "11111111111111111111111111111112",
      network: "devnet",
      quorum_key_id: "quorum",
      quorum_key_epoch: "4",
      not_before: "1000",
      expiry: "1801000",
      signature: "00".repeat(64),
    };
    const digest = "c17bed37b80feb7a2cdbe105d7b9db93214cad4dc85d39ed366ce7fe2e4db73c";
    expect(encodeLowerHex(viewGrantDigest(grant))).toBe(digest);
    expect(encodeLowerHex(viewGrantDigest({ ...grant, signature: "09".repeat(64) }))).toBe(digest);
    expect(encodeLowerHex(viewGrantMessage(new Uint8Array(32).fill(7), viewGrantDigest(grant)))).toBe(
      "ff736f6c616e61206f6666636861696e00633f364747049cf5b201551ec5172cbcd6517ff59ad0b38ee572f6fe1b7f8e15000107070707070707070707070707070707070707070707070707070707070707076600545350502f64656372797074696f6e2d736572766963652f766965772d6772616e742f76312f63313762656433376238306665623761326364626531303564376239646239333231346361643464633835643339656433363663653766653265346462373363",
    );
  });

  it("binds the release ID and rejects invalid Unicode before hashing", () => {
    expect(encodeLowerHex(serviceRequestDigest({ ...request, target_release_id: "release-2" }))).not.toBe(DIGEST);
    expect(() => serviceRequestDigest({ ...request, target_release_id: "\ud800" })).toThrow("InvalidCanonicalJson");
  });
});
