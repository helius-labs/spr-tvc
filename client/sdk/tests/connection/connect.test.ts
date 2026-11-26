import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { qosDecrypt, qosEncrypt } from "../../src/crypto/qos.js";
import { signP256Message, signP256Prehash } from "../../src/crypto/p256.js";
import { MAX_ENCRYPTED_REQUEST_BYTES } from "../../src/wire/constants.js";
import { canonicalizeJsonValue } from "../../src/wire/jcs.js";
import { decodeLowerHex, encodeLowerHex } from "../../src/wire/hex.js";
import type {
  PinnedReleaseAuthorities,
  ReleasePolicy,
  ServiceInfo,
  SignedReleasePolicy,
} from "../../src/wire/types.js";
import { policySigningDigest } from "../../src/attestation/release-policy.js";
import { fixtureManifestSet } from "../support/manifest-set.js";
import { fetchLiveServiceInfo, verifyLiveReplica, type DecryptionServiceConnectionConfig } from "../../src/connection/connect.js";
import { requestScope, type DecryptionServiceRequestOptions } from "../../src/connection/request.js";
import { createDecryptionServiceSession } from "../../src/connection/session.js";

const verifyBootProofMock = vi.hoisted(() => vi.fn());

vi.mock("../../src/attestation/boot-proof.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../src/attestation/boot-proof.js")>()),
  verifyBootProof: verifyBootProofMock,
}));

/** What the client verifies on first use. */
async function verify(config: DecryptionServiceConnectionConfig, options?: DecryptionServiceRequestOptions) {
  const scope = requestScope(options);
  try {
    return await createDecryptionServiceSession(config).context(scope.signal);
  } finally {
    scope.dispose();
  }
}

function secret(label: string): Uint8Array {
  return sha256(new TextEncoder().encode(label));
}

function qosPublic(
  encryptionSecret: Uint8Array,
  signingSecret: Uint8Array
): string {
  return encodeLowerHex(
    Uint8Array.from([
      ...p256.getPublicKey(encryptionSecret, false),
      ...p256.getPublicKey(signingSecret, false),
    ])
  );
}

function oversizedResponse(onPull: () => void): Response {
  const chunk = new Uint8Array(64 * 1024).fill(0x61);
  let pulls = 0;
  return new Response(
    new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        onPull();
        if (pulls > 4_096) {
          controller.close();
          return;
        }
        controller.enqueue(chunk);
      },
    }),
    { status: 200 },
  );
}

function connectFixture() {
  const quorumEncryptionSecret = secret("connect-quorum-encryption");
  const ephemeralEncryptionSecret = secret("connect-ephemeral-encryption");
  const ephemeralSigningSecret = secret("connect-ephemeral-signing");
  const authoritySecret = secret("connect-release-authority");
  const quorumPublicKey = qosPublic(quorumEncryptionSecret, secret("connect-quorum-signing"));
  const ephemeralPublicKey = qosPublic(
    ephemeralEncryptionSecret,
    ephemeralSigningSecret
  );
  const manifestDigest = "11".repeat(32);
  const executableDigest = "22".repeat(32);

  const policy: ReleasePolicy = {
    version: 1,
    network: "devnet",
    securityDomainId: "33".repeat(32),
    namespace: "fixture-namespace",
    manifestSet: fixtureManifestSet,
    minimumManifestNonce: "0",
    quorumKeyId: "quorum-connect",
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
  const signedPolicy: SignedReleasePolicy = {
    policy,
    authoritySetId: "connect-authorities",
    signatures: [
      {
        keyId: "connect-authority",
        signature: encodeLowerHex(
          signP256Prehash(authoritySecret, policySigningDigest(policy))
        ),
      },
    ],
  };
  const authorities: PinnedReleaseAuthorities = {
    authoritySetId: "connect-authorities",
    threshold: 1,
    minimumRevocationEpoch: "0",
    keys: [
      {
        keyId: "connect-authority",
        publicKey: encodeLowerHex(p256.getPublicKey(authoritySecret, false)),
      },
    ],
  };
  const info: ServiceInfo = {
    version: 1,
    network: "devnet",
    security_domain_id: policy.securityDomainId,
    release_id: "connect-poc",
    manifest_digest: manifestDigest,
    executable_digest: executableDigest,
    quorum_public_key: quorumPublicKey,
    quorum_key_id: policy.quorumKeyId,
    quorum_key_epoch: policy.quorumKeyEpoch,
    // /v1/info and /v1/ping may be served by different healthy replicas.
    supported_operations: ["ServicePublicKeys", "ServiceDecrypt"],
    max_encrypted_request_bytes: String(MAX_ENCRYPTED_REQUEST_BYTES),
    max_encrypted_response_bytes: String(MAX_ENCRYPTED_REQUEST_BYTES),
    proof_type: "spr.tvc.decryption_service.v1",
  };
  const expectedPcrs = {
    0: "44".repeat(48),
    1: "55".repeat(48),
    2: "66".repeat(48),
    3: "77".repeat(48),
  } as const;
  const bootProof = {
    ephemeralPublicKeyHex: ephemeralPublicKey,
    awsAttestationDocB64: "unused-by-mock",
    qosManifestB64: "unused-by-mock",
    qosManifestEnvelopeB64: "unused-by-mock",
    deploymentLabel: "connect-poc",
    enclaveApp: "wallet-dev",
    owner: "zolana",
    createdAt: { seconds: "1750000000", nanos: "0" },
  };

  /** The enclave's ping answer: its ephemeral key signs the decrypted challenge. */
  function pingAnswer(encryptedChallenge: string): string {
    const challengePayload = new TextDecoder().decode(
      qosDecrypt(quorumEncryptionSecret, decodeLowerHex(encryptedChallenge))
    );
    return canonicalizeJsonValue({
      version: 1,
      tvc_app_proof: {
        scheme: "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256",
        public_key: ephemeralPublicKey,
        proof_payload: challengePayload,
        signature: encodeLowerHex(
          signP256Message(
            ephemeralSigningSecret,
            new TextEncoder().encode(challengePayload)
          )
        ),
      },
    });
  }
  return {
    ephemeralPublicKey,
    manifestDigest,
    signedPolicy,
    authorities,
    info,
    expectedPcrs,
    bootProof,
    pingAnswer,
  };
}

describe("verification", () => {
  beforeEach(() =>
    verifyBootProofMock.mockReset().mockResolvedValue(undefined)
  );

  it("builds the request target from the pin and does not contact the enclave", async () => {
    const { signedPolicy, authorities, expectedPcrs } = connectFixture();
    const fetch = vi.fn();
    const resolveBootProof = vi.fn();
    const verified = await verify({
      backend: {
        endpoint: new URL("https://tvc.example.invalid/api/tvc/"),
        resolveBootProof,
      },
      network: "devnet",
      release: { releasePolicy: signedPolicy, releaseAuthorities: authorities, qosIdentityPcrs: expectedPcrs },
      nowMs: () => 1_750_000_000_000n,
      transport: { fetch },
    });
    expect(verified.target).toMatchObject({
      network: "devnet",
      quorumKeyId: "quorum-connect",
    });
    expect(fetch).not.toHaveBeenCalled();
    expect(resolveBootProof).not.toHaveBeenCalled();
  });

  it("reads the clock per use instead of freezing one instant", async () => {
    // A scalar nowMs would pin every freshness check to a single moment for the
    // client's whole life, quietly disabling attestation-age enforcement.
    const seen: bigint[] = [];
    let tick = 1_750_000_000_000n;
    const clock = () => {
      seen.push(tick);
      tick += 1_000n;
      return tick;
    };

    const policyFixture = JSON.parse(
      readFileSync(
        join(
          dirname(fileURLToPath(import.meta.url)),
          "../../../../wire/fixtures/signed-release-policy.json",
        ),
        "utf8",
      ),
    ) as Record<string, unknown>;

    const verified = verify({
      network: "devnet",
      backend: { endpoint: new URL("https://tvc.example.invalid") },
      release: {
        releasePolicy: policyFixture.signed as SignedReleasePolicy,
        releaseAuthorities: policyFixture.authorities as PinnedReleaseAuthorities,
        qosIdentityPcrs: { 0: "00", 1: "00", 2: "00", 3: "00" },
      },
      nowMs: clock,
      transport: { fetch: async () => new Response("{}", { status: 500 }) },
    });

    const context = await verified;
    expect(seen.length).toBeGreaterThan(0);
    context.nowMs();
    expect(seen.length).toBeGreaterThan(1);
  });
});

describe("the client's network", () => {
  it("refuses a release for another network before it fetches anything", async () => {
    const { signedPolicy, authorities, expectedPcrs } = connectFixture();
    const fetch = vi.fn();
    const verified = verify({
      network: "mainnet",
      backend: { endpoint: new URL("https://tvc.example.invalid"), resolveBootProof: vi.fn() },
      release: { releasePolicy: signedPolicy, releaseAuthorities: authorities, qosIdentityPcrs: expectedPcrs },
      nowMs: () => 1_750_000_000_000n,
      transport: { fetch },
    });
    await expect(verified).rejects.toMatchObject({ code: "NetworkMismatch" });
    expect(fetch).not.toHaveBeenCalled();
  });

});

describe("a live replica, before its release is signed", () => {
  beforeEach(() => {
    verifyBootProofMock.mockReset().mockResolvedValue(undefined);
  });

  function enclave(answer: (encryptedChallenge: string) => string) {
    const fetch = vi.fn(async (url: URL, init?: RequestInit) => {
      expect(url.pathname).toBe("/v1/ping");
      const request = JSON.parse(String(init?.body)) as { encrypted_challenge: string };
      try {
        return new Response(answer(request.encrypted_challenge), { status: 200 });
      } catch {
        // A challenge sealed to a key the replica does not hold.
        return new Response('{"error":"InvalidRequest"}', { status: 400 });
      }
    });
    return { fetch };
  }

  it("bounds release discovery before parsing the response", async () => {
    const { info } = connectFixture();
    const endpoint = new URL("https://app.example/base");
    const fetch = vi.fn(async (url: URL) => {
      expect(url.href).toBe("https://app.example/base/v1/info");
      return Response.json(info);
    });
    await expect(fetchLiveServiceInfo(endpoint, undefined, { fetch })).resolves.toEqual(info);

    let pulls = 0;
    fetch.mockResolvedValueOnce(oversizedResponse(() => { pulls += 1; }));
    await expect(fetchLiveServiceInfo(endpoint, undefined, { fetch })).rejects.toMatchObject({
      code: "ResponseTooLarge",
    });
    expect(pulls).toBeLessThan(4);
  });

  it("pings the approved Quorum key and attests the approved manifest", async () => {
    const { ephemeralPublicKey, manifestDigest, info, expectedPcrs, bootProof, pingAnswer } = connectFixture();
    const lookup = vi.fn().mockResolvedValue(bootProof);
    await verifyLiveReplica({
      endpoint: new URL("https://app.example"),
      info,
      approved: { manifestDigest: info.manifest_digest, executableDigest: info.executable_digest, quorumPublicKey: info.quorum_public_key },
      qosIdentityPcrs: expectedPcrs,
      turnkeyTrustRootId: "aws-nitro-root-g1",
      bootProof: lookup,
      transport: enclave(pingAnswer),
      nowMs: 1_750_000_000_000n,
    });
    expect(lookup).toHaveBeenCalledWith(ephemeralPublicKey, undefined);
    expect(verifyBootProofMock).toHaveBeenCalledWith({
      ephemeralPublicKey,
      bootProof,
      expectedManifestSha256: manifestDigest,
      expectedPcrs,
      nowMs: 1_750_000_000_000n,
    });
  });

  it.each(["ping", "Boot Proof lookup", "Boot Proof verification"])(
    "enforces the release deadline during %s",
    async (stage) => {
      const { info, expectedPcrs, bootProof, pingAnswer } = connectFixture();
      const deadline = new AbortController();
      const stalled = vi.fn(() => new Promise<never>(() => {}));
      const transport = stage === "ping" ? { fetch: stalled } : enclave(pingAnswer);
      const lookup = stage === "Boot Proof lookup" ? stalled : async () => bootProof;
      if (stage === "Boot Proof verification") verifyBootProofMock.mockImplementation(stalled);
      const pending = verifyLiveReplica({
        endpoint: new URL("https://app.example"),
        info,
        approved: { manifestDigest: info.manifest_digest, executableDigest: info.executable_digest, quorumPublicKey: info.quorum_public_key },
        qosIdentityPcrs: expectedPcrs,
        turnkeyTrustRootId: "aws-nitro-root-g1",
        bootProof: lookup,
        transport,
        signal: deadline.signal,
      });
      const timeout = new DOMException("release verification timed out", "TimeoutError");
      const rejected = expect(pending).rejects.toBe(timeout);
      await vi.waitFor(() => expect(stalled).toHaveBeenCalledOnce());
      deadline.abort(timeout);
      await rejected;
    },
  );

  it("is refused when another key answers, the Boot Proof fails, or the trust root is not the pinned one", async () => {
    const { info, expectedPcrs, bootProof, pingAnswer } = connectFixture();
    const input = {
      endpoint: new URL("https://app.example"),
      info,
      approved: { manifestDigest: info.manifest_digest, executableDigest: info.executable_digest, quorumPublicKey: info.quorum_public_key },
      qosIdentityPcrs: expectedPcrs,
      turnkeyTrustRootId: "aws-nitro-root-g1",
      bootProof: vi.fn().mockResolvedValue(bootProof),
      transport: enclave(pingAnswer),
    };
    const fetchUnapproved = vi.fn();
    for (const field of ["quorum_public_key", "manifest_digest", "executable_digest"] as const) {
      await expect(verifyLiveReplica({
        ...input, info: { ...info, [field]: "00" + info[field].slice(2) },
        transport: { fetch: fetchUnapproved },
      })).rejects.toMatchObject({ code: "ReleaseBindingMismatch" });
    }
    const prereleaseInfo = { ...info, ephemeral_public_key: bootProof.ephemeralPublicKeyHex };
    await expect(verifyLiveReplica({
      ...input, info: prereleaseInfo, transport: { fetch: fetchUnapproved },
    })).rejects.toMatchObject({ code: "UnknownJsonField" });
    expect(fetchUnapproved).not.toHaveBeenCalled();
    expect(input.bootProof).not.toHaveBeenCalled();
    // An answer to another challenge.
    const otherChallenge = encodeLowerHex(await qosEncrypt(
      p256.getPublicKey(secret("connect-quorum-encryption"), false),
      new TextEncoder().encode("another challenge"),
    ));
    const replayed = enclave(() => pingAnswer(otherChallenge));
    await expect(verifyLiveReplica({ ...input, transport: replayed })).rejects.toMatchObject({
      code: "TurnkeyEvidenceInvalid",
    });
    verifyBootProofMock.mockRejectedValueOnce(new Error("BootProofUnverified"));
    await expect(verifyLiveReplica(input)).rejects.toThrow("BootProofUnverified");
    const fetch = vi.fn();
    await expect(
      verifyLiveReplica({ ...input, turnkeyTrustRootId: "another-root", transport: { fetch } }),
    ).rejects.toMatchObject({ code: "ReleasePolicyInvalid" });
    expect(fetch).not.toHaveBeenCalled();
  });
});
