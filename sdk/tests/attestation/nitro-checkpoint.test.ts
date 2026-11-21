import { IDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { indexedDbNitroPolicyStore } from "../../src/attestation/nitro-checkpoint.js";

const scope = { network: "devnet" as const, securityDomainId: "aa".repeat(32) };
const first = { sequence: "1", minimumCustodyEpoch: "1", digest: "11".repeat(32) };
const next = { sequence: "2", minimumCustodyEpoch: "2", digest: "22".repeat(32) };

beforeEach(() => vi.stubGlobal("indexedDB", new IDBFactory()));
afterEach(() => vi.unstubAllGlobals());

describe("browser Nitro checkpoints", () => {
  it("persists the release floor across clients, isolated by network and domain", async () => {
    const writer = indexedDbNitroPolicyStore(scope);
    expect(await writer.current()).toBeUndefined();
    expect(await writer.accept(first)).toBe(true);
    expect(await writer.accept(next)).toBe(true);
    const reopened = indexedDbNitroPolicyStore(scope);
    expect(await reopened.current()).toEqual(next);
    expect(await reopened.accept(first)).toBe(false);
    expect(await reopened.accept({ ...first, sequence: "3" })).toBe(false);
    expect(await reopened.accept(next)).toBe(true);
    expect(await indexedDbNitroPolicyStore({ ...scope, network: "mainnet" }).current()).toBeUndefined();
    expect(await indexedDbNitroPolicyStore({ ...scope, securityDomainId: "bb".repeat(32) }).current()).toBeUndefined();
  });

  it("serializes two clients racing to accept different digests at one sequence", async () => {
    const other = { ...next, digest: "33".repeat(32) };
    const a = indexedDbNitroPolicyStore(scope);
    const b = indexedDbNitroPolicyStore(scope);
    const outcomes = await Promise.all([a.accept(next), b.accept(other)]);
    expect(outcomes.filter(Boolean)).toHaveLength(1);
    expect(await a.current()).toEqual(outcomes[0] ? next : other);
    expect(await b.current()).toEqual(await a.current());
  });

  it("fails closed when persistence is unavailable", () => {
    vi.stubGlobal("indexedDB", undefined);
    expect(() => indexedDbNitroPolicyStore(scope)).toThrow("checkpoint storage unavailable");
  });
});
