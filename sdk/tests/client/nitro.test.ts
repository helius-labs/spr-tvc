import { p256 } from "@noble/curves/p256";
import { address, type MessagePartialSigner } from "@solana/kit";
import type { ProofService } from "@heliuslabs/spr";
import { afterEach, describe, expect, it, vi } from "vitest";
import { nitroPolicySigningDigest, type NitroPolicy, type NitroTrust } from "../../src/attestation/nitro-policy.js";
import { createNitroDecryptionService } from "../../src/client/nitro.js";
import { signP256Prehash } from "../../src/crypto/p256.js";
import { encodeLowerHex } from "../../src/protocol/hex.js";

const secrets = [1, 2].map(value => new Uint8Array(32).fill(value));
const trust: NitroTrust = {
  network: "mainnet", securityDomainId: "55".repeat(32), noteSeedCommitment: "66".repeat(32),
  minimumSequence: "1", minimumCustodyEpoch: "1", threshold: 2,
  keys: secrets.map(secret => encodeLowerHex(p256.getPublicKey(secret, false))),
};
const policyUrl = new URL("https://policy.example.com/release.json");

function signedPolicy() {
  const now = Date.now();
  const policy: NitroPolicy = {
    network: trust.network, securityDomainId: trust.securityDomainId, noteSeedCommitment: trust.noteSeedCommitment,
    version: 1, sequence: "2", minimumCustodyEpoch: "1", validFromMs: String(now - 1000), expiresAtMs: String(now + 100_000),
    targets: [{
      endpoint: "https://replica.example.com/",
      releaseId: "nitro-2",
      custodyEpoch: "1",
    executableSha256: "77".repeat(32),
      pcrs: { 0: "11".repeat(48), 1: "22".repeat(48), 2: "33".repeat(48), 3: "44".repeat(48) },
    }],
  };
  return JSON.stringify({ policy, signatures: secrets.map((secret, index) => ({
    key: trust.keys[index],
    signature: encodeLowerHex(signP256Prehash(secret, nitroPolicySigningDigest(policy))),
  })) });
}

const signMessages = vi.fn<MessagePartialSigner["signMessages"]>();
const signer = { address: address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3"), signMessages };
const proofs = {} as ProofService;

afterEach(() => {
  vi.unstubAllGlobals();
  signMessages.mockClear();
});

describe("native client trust gate", () => {
  it("refuses to contact replicas or request approval if the durable checkpoint fails", async () => {
    const fetch = vi.fn(async () => new Response(signedPolicy()));
    vi.stubGlobal("fetch", fetch);
    const stored = vi.fn(async () => false);
    const client = createNitroDecryptionService({ trust, policyUrl, policyStore: { accept: stored } });
    await expect(client.open(signer, proofs)).rejects.toThrow("policy rollback or checkpoint");
    expect(stored).toHaveBeenCalledOnce();
    expect(fetch).toHaveBeenCalledOnce();
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("requires a bounded, verified policy before attempting to persist or contact a replica", async () => {
    const fetch = vi.fn(async () => new Response("x".repeat(32_769)));
    vi.stubGlobal("fetch", fetch);
    const stored = vi.fn(async () => true);
    const client = createNitroDecryptionService({ trust, policyUrl, policyStore: { accept: stored } });
    await expect(client.open(signer, proofs)).rejects.toThrow("ResponseTooLarge");
    expect(stored).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledOnce();
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("rejects unattested discovery before requesting a wallet signature", async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response(signedPolicy()))
      .mockResolvedValueOnce(new Response('{"info":{},"evidence":"00"}'));
    vi.stubGlobal("fetch", fetch);
    const client = createNitroDecryptionService({ trust, policyUrl, policyStore: { async accept() { return true; } } });
    await expect(client.open(signer, proofs)).rejects.toThrow("no authorized Nitro replica");
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls[1]?.[0].href).toBe("https://replica.example.com/v1/nitro/attestation");
    expect(fetch.mock.calls[1]?.[1]).toMatchObject({ redirect: "error", method: "POST" });
    expect(signMessages).not.toHaveBeenCalled();
  });
});
