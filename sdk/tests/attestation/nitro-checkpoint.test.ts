import { IDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { indexedDbNitroPolicyStore } from "../../src/attestation/nitro-checkpoint.js";

const scope = { network: "devnet" as const, securityDomainId: "aa".repeat(32) };
const first = { sequence: "1", minimumCustodyEpoch: "1", recoveryOnly: false, digest: "11".repeat(32) };
const next = { sequence: "2", minimumCustodyEpoch: "2", recoveryOnly: true, digest: "22".repeat(32) };

function agreed(checkpoint = next, previousPolicyDigest: string | null = first.digest) {
  const revision = { checkpoint, previousPolicyDigest };
  return [revision, revision] as const;
}

beforeEach(() => vi.stubGlobal("indexedDB", new IDBFactory()));
afterEach(() => vi.unstubAllGlobals());

describe("browser Nitro checkpoints", () => {
  it("persists the release floor across clients, isolated by network and domain", async () => {
    const writer = indexedDbNitroPolicyStore(scope);
    expect(await writer.current()).toBeUndefined();
    expect(await writer.accept(agreed(first, null))).toBe(true);
    expect(await writer.accept(agreed())).toBe(true);
    const reopened = indexedDbNitroPolicyStore(scope);
    expect(await reopened.current()).toEqual(next);
    expect(await reopened.accept(agreed(first, null))).toBe(false);
    expect(await reopened.accept(agreed({ ...first, sequence: "3" }, next.digest))).toBe(false);
    expect(await reopened.accept(agreed())).toBe(true);
    expect(await reopened.accept(agreed({ ...next, sequence: "3", recoveryOnly: false }, next.digest))).toBe(false);
    expect(await indexedDbNitroPolicyStore({ ...scope, network: "mainnet" }).current()).toBeUndefined();
    expect(await indexedDbNitroPolicyStore({ ...scope, securityDomainId: "bb".repeat(32) }).current()).toBeUndefined();
  });

  it("serializes two clients racing to accept different digests at one sequence", async () => {
    const other = { ...next, digest: "33".repeat(32) };
    const a = indexedDbNitroPolicyStore(scope);
    const b = indexedDbNitroPolicyStore(scope);
    const outcomes = await Promise.all([a.accept(agreed()), b.accept(agreed(other))]);
    expect(outcomes.filter(Boolean)).toHaveLength(1);
    expect(await a.current()).toEqual(outcomes[0] ? next : other);
    expect(await b.current()).toEqual(await a.current());
  });

  it("atomically serializes a revision and a successor from another branch", async () => {
    const a = indexedDbNitroPolicyStore(scope);
    const b = indexedDbNitroPolicyStore(scope);
    await a.accept(agreed(first, null));
    const fork = { ...next, digest: "33".repeat(32) };
    const newer = { ...next, sequence: "3", digest: "44".repeat(32) };
    const alternate = [agreed(newer, fork.digest)[0], agreed(fork)[0]] as const;
    const outcomes = await Promise.all([a.accept(agreed()), b.accept(alternate)]);
    expect(outcomes.filter(Boolean)).toHaveLength(1);
    expect(await b.current()).toEqual(outcomes[0] ? next : newer);
    expect(await a.current()).toEqual(await b.current());
  });

  it("fails closed when persistence is unavailable", () => {
    vi.stubGlobal("indexedDB", undefined);
    expect(() => indexedDbNitroPolicyStore(scope)).toThrow("checkpoint storage unavailable");
  });
});
