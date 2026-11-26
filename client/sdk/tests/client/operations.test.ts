import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { address } from "@solana/kit";
import { beforeEach, expect, it, vi } from "vitest";

import { policySigningDigest } from "../../src/attestation/release-policy.js";
import { createDecryptionService } from "../../src/client/decryption.js";
import { signP256Message, signP256Prehash } from "../../src/crypto/p256.js";
import { qosDecrypt } from "../../src/crypto/qos.js";
import { MAX_ENCRYPTED_REQUEST_BYTES, TVC_APP_PROOF_SCHEME } from "../../src/wire/constants.js";
import { canonicalizeJsonValue } from "../../src/wire/jcs.js";
import { decodeLowerHex, encodeLowerHex } from "../../src/wire/hex.js";
import type { ReleaseTrust } from "../../src/wire/releases.js";
import type { ReleasePolicy, ServiceInfo } from "../../src/wire/types.js";

const verifyBootProofMock = vi.hoisted(() => vi.fn());

vi.mock("../../src/attestation/boot-proof.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../src/attestation/boot-proof.js")>()),
  verifyBootProof: verifyBootProofMock,
}));

const owner = address("11111111111111111111111111111111");

function secret(label: string): Uint8Array {
  return sha256(new TextEncoder().encode(label));
}

function qosPublic(encryptionSecret: Uint8Array, signingSecret: Uint8Array): string {
  return encodeLowerHex(Uint8Array.from([
    ...p256.getPublicKey(encryptionSecret, false),
    ...p256.getPublicKey(signingSecret, false),
  ]));
}

function fixture() {
  const quorumEncryptionSecret = secret("gatekeeper-quorum-encryption");
  const ephemeralSigningSecret = secret("gatekeeper-ephemeral-signing");
  const authoritySecret = secret("gatekeeper-authority");
  const quorumPublicKey = qosPublic(quorumEncryptionSecret, secret("gatekeeper-quorum-signing"));
  const ephemeralPublicKey = qosPublic(secret("gatekeeper-ephemeral-encryption"), ephemeralSigningSecret);
  const manifestDigest = "11".repeat(32);
  const executableDigest = "22".repeat(32);
  const policy: ReleasePolicy = {
    version: 1,
    releaseId: "gatekeeper",
    network: "devnet",
    securityDomainId: "33".repeat(32),
    acceptedManifestDigests: [manifestDigest],
    acceptedExecutableDigests: [executableDigest],
    quorumKeyId: "quorum",
    quorumKeyEpoch: "1",
    quorumPublicKey,
    allowedOperations: ["ServicePublicKeys", "ServiceDecrypt"],
    maxEncryptedRequestBytes: MAX_ENCRYPTED_REQUEST_BYTES,
    maxEncryptedResponseBytes: MAX_ENCRYPTED_REQUEST_BYTES,
    turnkeyTrustRootId: "aws-nitro-root-g1",
    validFromMs: "1700000000000",
    expiresAtMs: "1800000000000",
    revocationEpoch: "0",
  };
  const release: ReleaseTrust = {
    releasePolicy: {
      policy,
      authoritySetId: "authorities",
      signatures: [{
        keyId: "authority",
        signature: encodeLowerHex(signP256Prehash(authoritySecret, policySigningDigest(policy))),
      }],
    },
    releaseAuthorities: {
      authoritySetId: "authorities",
      threshold: 1,
      minimumRevocationEpoch: "0",
      keys: [{ keyId: "authority", publicKey: encodeLowerHex(p256.getPublicKey(authoritySecret, false)) }],
    },
    qosIdentityPcrs: { 0: "44".repeat(48), 1: "55".repeat(48), 2: "66".repeat(48), 3: "77".repeat(48) },
  };
  const info: ServiceInfo = {
    version: 1,
    network: "devnet",
    security_domain_id: policy.securityDomainId,
    release_id: policy.releaseId,
    manifest_digest: manifestDigest,
    executable_digest: executableDigest,
    quorum_public_key: quorumPublicKey,
    quorum_key_id: policy.quorumKeyId,
    quorum_key_epoch: policy.quorumKeyEpoch,
    supported_operations: ["ServicePublicKeys", "ServiceDecrypt"],
    max_encrypted_request_bytes: String(MAX_ENCRYPTED_REQUEST_BYTES),
    max_encrypted_response_bytes: String(MAX_ENCRYPTED_REQUEST_BYTES),
    proof_type: "spr.tvc.decryption_service.v1",
  };
  const sessionBoot = { ephemeralPublicKeyHex: ephemeralPublicKey, awsAttestationDocB64: "session-proof" };
  const operationBoot = { ephemeralPublicKeyHex: ephemeralPublicKey, awsAttestationDocB64: "operation-proof" };
  function ping(encryptedChallenge: string) {
    const challengePayload = new TextDecoder().decode(
      qosDecrypt(quorumEncryptionSecret, decodeLowerHex(encryptedChallenge)),
    );
    return {
      version: 1,
      tvc_app_proof: {
        scheme: TVC_APP_PROOF_SCHEME,
        public_key: ephemeralPublicKey,
        proof_payload: challengePayload,
        signature: encodeLowerHex(signP256Message(ephemeralSigningSecret, new TextEncoder().encode(challengePayload))),
      },
    };
  }
  return { release, info, sessionBoot, operationBoot, quorumEncryptionSecret, ephemeralPublicKey, ephemeralSigningSecret, ping };
}

beforeEach(() => {
  verifyBootProofMock.mockReset().mockResolvedValue(undefined);
});

it("refuses an endpoint that is not an https origin", () => {
  const { release } = fixture();
  expect(() => createDecryptionService({
    network: "devnet",
    endpoint: new URL("http://gate.example"),
    apiKey: "test-key",
    release,
  })).toThrow(expect.objectContaining({ code: "InvalidServiceConfig" }));
});

it("checks the boot proof on the operation reply", async () => {
  const { release, operationBoot, quorumEncryptionSecret, ephemeralPublicKey, ephemeralSigningSecret } = fixture();
  const urls: string[] = [];
  const service = createDecryptionService({
    network: "devnet",
    endpoint: new URL("https://gate.example"),
    apiKey: "test-key",
    nowMs: () => 1750000000000n,
    release,
    transport: {
      async fetch(url, init) {
        urls.push(url.pathname);
        expect(new Headers(init?.headers).get("x-api-key")).toBe("test-key");
        const body = JSON.parse(String(init?.body)) as { ciphertext?: string };
        const request = JSON.parse(new TextDecoder().decode(
          qosDecrypt(quorumEncryptionSecret, decodeLowerHex(body.ciphertext ?? "")),
        )) as { request_id: string };
        const proofPayload = canonicalizeJsonValue({ operation: "unchecked" });
        return Response.json({
          response: {
            version: 1,
            request_id: request.request_id,
            encrypted_result: "00",
            tvc_app_proof: {
              scheme: TVC_APP_PROOF_SCHEME,
              public_key: ephemeralPublicKey,
              proof_payload: proofPayload,
              signature: encodeLowerHex(signP256Message(ephemeralSigningSecret, new TextEncoder().encode(proofPayload))),
            },
          },
          bootProof: operationBoot,
        });
      },
    },
  });
  await expect(service.address(owner)).rejects.toThrow();
  expect(urls).toEqual(["/v1/decryption/operations"]);
  expect(verifyBootProofMock).toHaveBeenCalledTimes(1);
  expect(verifyBootProofMock).toHaveBeenCalledWith(expect.objectContaining({ bootProof: operationBoot }));
});
