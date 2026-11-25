import { p256 } from "@noble/curves/p256";
import { address } from "@solana/kit";
import { expect, it } from "vitest";

import { createOperationsDecryptionService } from "../../src/client/decryption.js";
import { encodeLowerHex } from "../../src/wire/hex.js";
import type { ReleaseTrust } from "../../src/wire/releases.js";

const owner = address("11111111111111111111111111111111");

function release(): ReleaseTrust {
  const publicKey = encodeLowerHex(p256.getPublicKey(new Uint8Array(32).fill(1), false));
  const pcr = "aa".repeat(48);
  return {
    releasePolicy: {
      policy: {
        version: 1,
        releaseId: "release",
        network: "devnet",
        securityDomainId: "00".repeat(32),
        acceptedManifestDigests: ["11".repeat(32)],
        acceptedExecutableDigests: ["22".repeat(32)],
        quorumKeyId: "quorum",
        quorumKeyEpoch: "1",
        quorumPublicKey: publicKey + publicKey,
        allowedOperations: ["ServicePublicKeys", "ServiceDecrypt"],
        maxEncryptedRequestBytes: 1_000_000,
        maxEncryptedResponseBytes: 1_000_000,
        turnkeyTrustRootId: "root",
        validFromMs: "0",
        expiresAtMs: "9999999999999",
        revocationEpoch: "0",
      },
      authoritySetId: "set",
      signatures: [],
    },
    releaseAuthorities: {
      authoritySetId: "set",
      threshold: 1,
      keys: [],
      minimumRevocationEpoch: "0",
    },
    qosIdentityPcrs: { 0: pcr, 1: pcr, 2: pcr, 3: pcr },
  };
}

it("posts keys to /v1/operations and does not discover or ping", async () => {
  const urls: string[] = [];
  const service = createOperationsDecryptionService({
    network: "devnet",
    endpoint: new URL("https://gate.example"),
    nowMs: () => 1000n,
    release: release(),
    transport: {
      async fetch(url) {
        urls.push(url.pathname);
        return new Response("no", { status: 503 });
      },
    },
  });
  await expect(service.address(owner)).rejects.toThrow();
  expect(urls).toEqual(["/v1/operations"]);
});
