import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { address, signatureBytes, type MessagePartialSigner } from "@solana/kit";
import { ViewingKey, type ProofService } from "@heliuslabs/spr";
import { IDBFactory } from "fake-indexeddb";
import { afterEach, describe, expect, it, vi } from "vitest";
import { verifyNativeNitroEvidence } from "../../src/attestation/boot-proof.js";
import { indexedDbNitroPolicyStore } from "../../src/attestation/nitro-checkpoint.js";
import { nitroCustodySigningDigest, nitroPolicySigningDigest, type NitroPolicy, type NitroPolicyCheckpoint, type NitroTrust } from "../../src/attestation/nitro-policy.js";
import { createNitroDecryptionService } from "../../src/client/nitro.js";
import { signP256Message, signP256Prehash } from "../../src/crypto/p256.js";
import { qosDecrypt, qosEncrypt } from "../../src/crypto/qos.js";
import { TVC_APP_PROOF_SCHEME } from "../../src/protocol/constants.js";
import { SERVICE_PROOF_TYPE, serviceRequestDigest, type ServiceRequest } from "../../src/protocol/decryption.js";
import { resultDigest } from "../../src/protocol/digest.js";
import { encodeLowerHex, requireHex } from "../../src/protocol/hex.js";
import { canonicalizeJsonValue } from "../../src/protocol/jcs.js";

vi.mock("../../src/attestation/boot-proof.js", () => ({ verifyNativeNitroEvidence: vi.fn() }));

const secrets = [1, 2].map(value => new Uint8Array(32).fill(value));
const custodySecrets = [5, 6, 7].map(value => new Uint8Array(32).fill(value));
const trust: NitroTrust = {
  network: "mainnet", securityDomainId: "55".repeat(32), noteSeedCommitment: "66".repeat(32),
  minimumSequence: "1", minimumCustodyEpoch: "1", threshold: 2,
  publications: [
    { bucket: "release-test", region: "eu-north-1", account: "000000000001" },
    { bucket: "release-peer", region: "eu-west-1", account: "000000000002" },
  ],
  keys: secrets.map(secret => encodeLowerHex(p256.getPublicKey(secret, false))),
  custodyKeys: custodySecrets.map(secret => encodeLowerHex(p256.getPublicKey(secret, false))),
};

function signedPolicy(overrides: Partial<NitroPolicy> = {}) {
  const now = Date.now();
  const policy: NitroPolicy = {
    network: trust.network, securityDomainId: trust.securityDomainId, noteSeedCommitment: trust.noteSeedCommitment,
    version: 1, action: "activate", sequence: "2", minimumCustodyEpoch: "1",
    previousPolicyDigest: "88".repeat(32),
    validFromMs: String(now - 1000), expiresAtMs: String(now + 100_000),
    targets: [{
      endpoint: "https://replica.example.com/",
      releaseId: "nitro-2",
      custodyEpoch: "1", custodyDigest: "99".repeat(32),
      executableSha256: "77".repeat(32),
      pcrs: { 0: "11".repeat(48), 1: "22".repeat(48), 2: "33".repeat(48), 3: "44".repeat(48) },
    }],
    ...overrides,
  };
  return JSON.stringify({ policy, signatures: secrets.map((secret, index) => ({
    key: trust.keys[index],
    signature: encodeLowerHex(signP256Prehash(secret, nitroPolicySigningDigest(policy))),
  })), custodySignatures: policy.action === "activate" ? custodySecrets.slice(0, 2).map((secret, index) => ({
    key: trust.custodyKeys[index], signature: encodeLowerHex(signP256Prehash(secret, nitroCustodySigningDigest(policy))),
  })) : [] });
}

function policyHeads(fetch = vi.fn(), first = signedPolicy(), second = first) {
  return fetch.mockResolvedValueOnce(new Response(first)).mockResolvedValueOnce(new Response(second));
}

function publicPair(boot: readonly Uint8Array[]) {
  return boot.map(secret => encodeLowerHex(p256.getPublicKey(secret, false))).join("");
}

function attestedDiscovery(custodyDigest = "99".repeat(32), boot = secrets, certificateValidThroughMs = BigInt(Date.now()) + 120_000n) {
  const pair = publicPair(boot);
  const executable = "77".repeat(32);
  const identity = sha256(Uint8Array.from([
    ...new TextEncoder().encode("SPR/native-nitro/release/v1"),
    ...requireHex(executable, 32), ...requireHex(trust.noteSeedCommitment, 32), ...requireHex(custodyDigest, 32),
  ]));
  vi.mocked(verifyNativeNitroEvidence).mockResolvedValue({
    proofKey: pair, certificateValidFromMs: BigInt(Date.now()) - 1_000n, certificateValidThroughMs,
  });
  return Response.json({ info: {
    version: 1, network: trust.network, security_domain_id: trust.securityDomainId, release_id: "nitro-2",
    manifest_digest: encodeLowerHex(identity), executable_digest: executable, quorum_public_key: pair,
    quorum_key_id: encodeLowerHex(sha256(requireHex(pair, 130))), quorum_key_epoch: "1",
    supported_operations: ["ServicePublicKeys", "ServiceDecrypt"], proof_type: "spr.tvc.decryption_service.v1",
    max_encrypted_request_bytes: "262144", max_encrypted_response_bytes: "262144",
  }, evidence: "aa" });
}

const signMessages = vi.fn<MessagePartialSigner["signMessages"]>();
const signer = { address: address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3"), signMessages };
const proofs = {} as ProofService;
const emptyStore = { async current() { return undefined; } };
const replacementBoot = [3, 4].map(value => new Uint8Array(32).fill(value));
const replacement = "https://replacement.example.com/";

function twoReplicas() {
  const { policy } = JSON.parse(signedPolicy()) as { policy: NitroPolicy };
  const first = policy.targets[0]!;
  return signedPolicy({ targets: [first, { ...first, endpoint: replacement }] });
}

function checkpointStore() {
  let current: NitroPolicyCheckpoint | undefined;
  return {
    async current() { return current; },
    async accept(next: NitroPolicyCheckpoint) { current = next; return true; },
  };
}

function lookupReply(init: RequestInit, boot: readonly Uint8Array[]) {
  const { ciphertext } = JSON.parse(String(init.body)) as { ciphertext: string };
  const request = JSON.parse(new TextDecoder().decode(qosDecrypt(boot[0]!, requireHex(ciphertext)))) as ServiceRequest;
  expect(request.operation).toEqual({ type: "PublicKeys", address: signer.address });
  const viewing = ViewingKey.generate();
  const result = canonicalizeJsonValue({ type: "PublicKeys", viewing_public_key: encodeLowerHex(viewing.publicKey().toBytes()),
    nullifier_public_key: "01".repeat(32) });
  viewing.destroy();
  const text = new TextEncoder();
  const reply = qosEncrypt(requireHex(request.client_response_public_key), text.encode(result));
  const proof = canonicalizeJsonValue({
    type: SERVICE_PROOF_TYPE, version: 1, request_id: request.request_id,
    request_digest: encodeLowerHex(serviceRequestDigest(request)), result_digest: encodeLowerHex(resultDigest(reply)),
    operation: "ServicePublicKeys",
  });
  return Response.json({ version: 1, request_id: request.request_id, encrypted_result: encodeLowerHex(reply), tvc_app_proof: {
    scheme: TVC_APP_PROOF_SCHEME, public_key: publicPair(boot), proof_payload: proof,
    signature: encodeLowerHex(signP256Message(boot[1]!, text.encode(proof))),
  } });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.mocked(verifyNativeNitroEvidence).mockReset();
  signMessages.mockClear();
});

describe("native client trust gate", () => {
  it("refuses a release-only activation before replica contact, checkpoint writes or wallet approval", async () => {
    const activation = JSON.parse(signedPolicy());
    const fetch = policyHeads(vi.fn(), JSON.stringify({ ...activation, custodySignatures: [] }));
    const accept = vi.fn(async () => true);
    vi.stubGlobal("fetch", fetch);
    const client = createNitroDecryptionService({ trust, policyStore: { ...emptyStore, accept } });
    await expect(client.open(signer, proofs)).rejects.toThrow("ReleasePolicyInvalid");
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(verifyNativeNitroEvidence).not.toHaveBeenCalled();
    expect(accept).not.toHaveBeenCalled();
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("reattests at certificate expiry before sending another operation", async () => {
    vi.useFakeTimers();
    try {
      const policy = signedPolicy();
      const validThrough = BigInt(Date.now()) + 1_000n;
      const initialDiscovery = attestedDiscovery(undefined, secrets, validThrough);
      const fetch = policyHeads(vi.fn(), policy)
        .mockResolvedValueOnce(initialDiscovery)
        .mockImplementationOnce((_url, init) => lookupReply(init, secrets));
      policyHeads(fetch, policy).mockImplementationOnce(() => attestedDiscovery(undefined, replacementBoot))
        .mockImplementationOnce((_url, init) => lookupReply(init, replacementBoot));
      vi.stubGlobal("fetch", fetch);
      const client = createNitroDecryptionService({ trust, policyStore: checkpointStore() });
      await client.address(signer.address);
      vi.setSystemTime(Number(validThrough + 1n));
      await client.address(signer.address);
      expect(verifyNativeNitroEvidence).toHaveBeenCalledTimes(2);
      expect(fetch.mock.calls.map(([url]) => url.pathname).filter(path => !path.endsWith("policy.json"))).toEqual([
        "/v1/nitro/attestation", "/v1/operations", "/v1/nitro/attestation", "/v1/operations",
      ]);
    } finally { vi.useRealTimers(); }
  });

  it("sends no operation if certificate validity ends during the checkpoint write", async () => {
    vi.useFakeTimers();
    try {
      const store = checkpointStore();
      const validThrough = BigInt(Date.now()) + 1_000n;
      const fetch = policyHeads().mockResolvedValueOnce(attestedDiscovery(undefined, secrets, validThrough));
      vi.stubGlobal("fetch", fetch);
      const client = createNitroDecryptionService({ trust, policyStore: {
        current: store.current,
        async accept(checkpoint) {
          vi.setSystemTime(Number(validThrough + 1n));
          return store.accept(checkpoint);
        },
      } });
      await expect(client.address(signer.address)).rejects.toMatchObject({ code: "ExpiredRequest" });
      expect(fetch).toHaveBeenCalledTimes(3);
    } finally { vi.useRealTimers(); }
  });

  it("retries an unsigned lookup once with fresh evidence after a replica stalls mid-response", async () => {
    vi.useFakeTimers();
    try {
      const policy = twoReplicas();
      const cancel = vi.fn();
      const fetch = vi.fn(async (url: URL, init: RequestInit) => {
        if (url.pathname.endsWith("/policy.json")) return new Response(policy);
        const next = url.origin === new URL(replacement).origin;
        const boot = next ? replacementBoot : secrets;
        if (url.pathname === "/v1/nitro/attestation") return attestedDiscovery(undefined, boot);
        if (!next) return new Response(new ReadableStream({ cancel }));
        return lookupReply(init, boot);
      });
      vi.stubGlobal("fetch", fetch);
      const client = createNitroDecryptionService({ trust, policyStore: checkpointStore() });
      const result = expect(client.address(signer.address)).resolves.toBeDefined();
      await vi.advanceTimersByTimeAsync(12_000);
      await result;
      expect(cancel).toHaveBeenCalledOnce();
      expect(fetch.mock.calls.map(([url]) => url.href).filter(url => !url.endsWith("policy.json"))).toEqual([
        "https://replica.example.com/v1/nitro/attestation", "https://replica.example.com/v1/operations",
        `${replacement}v1/nitro/attestation`, `${replacement}v1/operations`,
      ]);
      expect(verifyNativeNitroEvidence).toHaveBeenCalledTimes(2);
      expect(signMessages).not.toHaveBeenCalled();
    } finally { vi.useRealTimers(); }
  });

  it("leaves a failed signed request with its original boot and reattests on the next explicit lookup", async () => {
    const policy = twoReplicas();
    let requests = 0;
    const fetch = vi.fn(async (url: URL, init: RequestInit) => {
      if (url.pathname.endsWith("/policy.json")) return new Response(policy);
      const boot = url.hostname === "replica.example.com" ? secrets : replacementBoot;
      if (url.pathname === "/v1/nitro/attestation") return attestedDiscovery(undefined, boot);
      if (++requests === 2) {
        const { ciphertext } = JSON.parse(String(init.body)) as { ciphertext: string };
        const request = JSON.parse(new TextDecoder().decode(qosDecrypt(boot[0]!, requireHex(ciphertext)))) as ServiceRequest;
        expect(request.operation).toMatchObject({ type: "Decrypt", signature: "01".repeat(64) });
        return new Response(null, { status: 503 });
      }
      return lookupReply(init, boot);
    });
    vi.stubGlobal("fetch", fetch);
    signMessages.mockResolvedValueOnce([{ [signer.address]: signatureBytes(new Uint8Array(64).fill(1)) }]);
    const client = createNitroDecryptionService({ trust, policyStore: checkpointStore() });
    await expect(client.open(signer, proofs)).rejects.toMatchObject({ code: "OperationUnavailable", status: 503 });
    expect(requests).toBe(2);
    expect(signMessages).toHaveBeenCalledOnce();
    await expect(client.address(signer.address)).resolves.toBeDefined();
    expect(fetch.mock.calls.at(-1)?.[0].href).toBe(`${replacement}v1/operations`);
    expect(requests).toBe(3);
    expect(signMessages).toHaveBeenCalledOnce();
  });

  it.each([[400, 2], [408, 2], [503, 2], [429, 1]])("caps lookup attempts on HTTP %s at %s", async (status, attempts) => {
    const policy = twoReplicas();
    const fetch = vi.fn(async (url: URL) => {
      if (url.pathname.endsWith("/policy.json")) return new Response(policy);
      if (url.pathname === "/v1/nitro/attestation") return attestedDiscovery();
      return new Response(null, { status, headers: { "retry-after": "5" } });
    });
    vi.stubGlobal("fetch", fetch);
    const client = createNitroDecryptionService({ trust, policyStore: checkpointStore() });
    await expect(client.address(signer.address)).rejects.toMatchObject({ status, retryAfter: "5" });
    expect(fetch.mock.calls.filter(([url]) => url.pathname === "/v1/operations")).toHaveLength(attempts);
  });
  it("refuses to send an operation or request approval if the qualified checkpoint cannot persist", async () => {
    const fetch = policyHeads().mockResolvedValueOnce(attestedDiscovery());
    vi.stubGlobal("fetch", fetch);
    const stored = vi.fn(async () => false);
    const client = createNitroDecryptionService({ trust, policyStore: { ...emptyStore, accept: stored } });
    await expect(client.open(signer, proofs)).rejects.toThrow("policy rollback or checkpoint");
    expect(stored).toHaveBeenCalledOnce();
    expect(verifyNativeNitroEvidence).toHaveBeenCalledBefore(stored);
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(fetch.mock.calls[0]?.[0].href).toBe(`https://release-test.s3.eu-north-1.amazonaws.com/spr-release/mainnet/${trust.securityDomainId}/policy.json`);
    expect(fetch.mock.calls[1]?.[0].href).toBe(`https://release-peer.s3.eu-west-1.amazonaws.com/spr-release/mainnet/${trust.securityDomainId}/policy.json`);
    for (const [index, publication] of trust.publications.entries()) {
      expect(new Headers(fetch.mock.calls[index]?.[1].headers).get("x-amz-expected-bucket-owner")).toBe(publication.account);
    }
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("requires a bounded, verified policy before attempting to persist or contact a replica", async () => {
    const fetch = vi.fn(async () => new Response("x".repeat(32_769)));
    vi.stubGlobal("fetch", fetch);
    const stored = vi.fn(async () => true);
    const client = createNitroDecryptionService({ trust, policyStore: { ...emptyStore, accept: stored } });
    await expect(client.open(signer, proofs)).rejects.toThrow("ResponseTooLarge");
    expect(stored).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("rejects unattested discovery before requesting a wallet signature", async () => {
    const fetch = policyHeads()
      .mockResolvedValueOnce(new Response('{"info":{},"evidence":"00"}'));
    vi.stubGlobal("fetch", fetch);
    const client = createNitroDecryptionService({ trust, policyStore: { ...emptyStore, async accept() { return true; } } });
    await expect(client.open(signer, proofs)).rejects.toThrow("no authorized Nitro replica");
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(fetch.mock.calls[2]?.[0].href).toBe("https://replica.example.com/v1/nitro/attestation");
    expect(fetch.mock.calls[2]?.[1]).toMatchObject({ redirect: "error", method: "POST" });
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("rejects discovery for a different custody record at the expected epoch", async () => {
    const fetch = policyHeads().mockResolvedValueOnce(attestedDiscovery("ab".repeat(32)));
    vi.stubGlobal("fetch", fetch);
    const accept = vi.fn(async () => true);
    const client = createNitroDecryptionService({ trust, policyStore: { ...emptyStore, accept } });
    await expect(client.open(signer, proofs)).rejects.toThrow("no authorized Nitro replica");
    expect(accept).not.toHaveBeenCalled();
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("preserves the previous floor and sequence when a signed activation cannot attest", async () => {
    const old = signedPolicy();
    const targets = JSON.parse(old).policy.targets.map((target: NitroPolicy["targets"][number]) => ({ ...target, custodyEpoch: "2" }));
    const fetch = policyHeads(vi.fn(), signedPolicy({ sequence: "3", minimumCustodyEpoch: "2", targets }))
      .mockResolvedValueOnce(new Response(null, { status: 503 }));
    policyHeads(fetch, old).mockResolvedValueOnce(attestedDiscovery());
    vi.stubGlobal("fetch", fetch);
    const stored = vi.fn(async () => false);
    const client = createNitroDecryptionService({ trust, policyStore: { ...emptyStore, accept: stored } });
    await expect(client.open(signer, proofs)).rejects.toThrow("no authorized Nitro replica");
    expect(stored).not.toHaveBeenCalled();
    await expect(client.open(signer, proofs)).rejects.toThrow("checkpoint unavailable");
    expect(stored).toHaveBeenCalledWith(expect.objectContaining({ sequence: "2", minimumCustodyEpoch: "1" }));
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("persists only a primary revocation and refuses rollback before attestation after reopening the client", async () => {
    const old = signedPolicy();
    const previousPolicyDigest = encodeLowerHex(nitroPolicySigningDigest(JSON.parse(old).policy));
    const revoked = signedPolicy({ action: "revoke", sequence: "3", previousPolicyDigest, minimumCustodyEpoch: "2", targets: [] });
    const fetch = policyHeads(vi.fn(), old, revoked);
    policyHeads(fetch, revoked, old);
    policyHeads(fetch, old);
    policyHeads(fetch, signedPolicy({ sequence: "4" }));
    vi.stubGlobal("fetch", fetch);
    vi.stubGlobal("indexedDB", new IDBFactory());
    const client = createNitroDecryptionService({ trust });
    const stored = indexedDbNitroPolicyStore(trust);
    await expect(client.open(signer, proofs)).rejects.toThrow("ReleasePolicyInvalid");
    expect(await stored.current()).toBeUndefined();
    await expect(client.open(signer, proofs)).rejects.toThrow("ReleasePolicyRevoked");
    const checkpoint = await stored.current();
    expect(checkpoint).toMatchObject({ sequence: "3", minimumCustodyEpoch: "2" });

    const reopened = createNitroDecryptionService({ trust });
    await expect(reopened.open(signer, proofs)).rejects.toThrow("policy rollback");
    await expect(reopened.open(signer, proofs)).rejects.toThrow("policy rollback");
    expect(await stored.current()).toEqual(checkpoint);
    expect(fetch).toHaveBeenCalledTimes(8);
    expect(verifyNativeNitroEvidence).not.toHaveBeenCalled();
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("refuses to use a connection superseded in another SDK instance", async () => {
    const fetch = policyHeads().mockResolvedValueOnce(attestedDiscovery());
    vi.stubGlobal("fetch", fetch);
    const store = {
      async accept() { return true; },
      current: vi.fn().mockResolvedValueOnce(undefined)
        .mockResolvedValue({ sequence: "3", minimumCustodyEpoch: "2", digest: "aa".repeat(32) }),
    };
    const client = createNitroDecryptionService({ trust, policyStore: store });
    await expect(client.open(signer, proofs)).rejects.toThrow("ReleasePolicySuperseded");
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("requires the second publication even if the first returned a usable signed policy", async () => {
    const fetch = vi.fn().mockResolvedValueOnce(new Response(signedPolicy()))
      .mockResolvedValueOnce(new Response(null, { status: 503 }));
    vi.stubGlobal("fetch", fetch);
    const accept = vi.fn(async () => true);
    const client = createNitroDecryptionService({ trust, policyStore: { ...emptyStore, accept } });
    await expect(client.open(signer, proofs)).rejects.toMatchObject({ code: "ReleasePolicyInvalid", status: 503 });
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(accept).not.toHaveBeenCalled();
    expect(signMessages).not.toHaveBeenCalled();
  });
});
