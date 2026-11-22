import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { address, type MessagePartialSigner } from "@solana/kit";
import type { ProofService } from "@heliuslabs/spr";
import { IDBFactory } from "fake-indexeddb";
import { afterEach, describe, expect, it, vi } from "vitest";
import { verifyNativeNitroEvidence } from "../../src/attestation/boot-proof.js";
import { indexedDbNitroPolicyStore } from "../../src/attestation/nitro-checkpoint.js";
import { nitroPolicySigningDigest, type NitroPolicy, type NitroTrust } from "../../src/attestation/nitro-policy.js";
import { createNitroDecryptionService } from "../../src/client/nitro.js";
import { signP256Prehash } from "../../src/crypto/p256.js";
import { encodeLowerHex, requireHex } from "../../src/protocol/hex.js";

vi.mock("../../src/attestation/boot-proof.js", () => ({ verifyNativeNitroEvidence: vi.fn() }));

const secrets = [1, 2].map(value => new Uint8Array(32).fill(value));
const trust: NitroTrust = {
  network: "mainnet", securityDomainId: "55".repeat(32), noteSeedCommitment: "66".repeat(32),
  minimumSequence: "1", minimumCustodyEpoch: "1", threshold: 2,
  publications: [
    { bucket: "release-test", region: "eu-north-1", account: "000000000001" },
    { bucket: "release-peer", region: "eu-west-1", account: "000000000002" },
  ],
  keys: secrets.map(secret => encodeLowerHex(p256.getPublicKey(secret, false))),
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
  })) });
}

function policyHeads(fetch = vi.fn(), first = signedPolicy(), second = first) {
  return fetch.mockResolvedValueOnce(new Response(first)).mockResolvedValueOnce(new Response(second));
}

function attestedDiscovery(custodyDigest = "99".repeat(32)) {
  const pair = trust.keys.join("");
  const executable = "77".repeat(32);
  const identity = sha256(Uint8Array.from([
    ...new TextEncoder().encode("SPR/native-nitro/release/v1"),
    ...requireHex(executable, 32), ...requireHex(trust.noteSeedCommitment, 32), ...requireHex(custodyDigest, 32),
  ]));
  vi.mocked(verifyNativeNitroEvidence).mockResolvedValue(pair);
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

afterEach(() => {
  vi.unstubAllGlobals();
  vi.mocked(verifyNativeNitroEvidence).mockReset();
  signMessages.mockClear();
});

describe("native client trust gate", () => {
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
