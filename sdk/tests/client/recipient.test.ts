import { ShieldedAddress, ShieldedPublicKey, USER_REGISTRY_PROGRAM_ID, ViewingKey, type Bytes32 } from "@heliuslabs/spr";
import { address, getAddressEncoder, getProgramDerivedAddress, type Address } from "@solana/kit";
import { beforeEach, expect, it, vi } from "vitest";
import { createLocalDecryptionService } from "../../src/testing.js";
import { genesisHashForNetwork } from "../../src/protocol/network.js";
import { resolvePaymentAddress } from "../../src/client/recipient.js";

const recipient = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
function shielded(owner: Address): ShieldedAddress {
  const viewing = ViewingKey.generate();
  try {
    return ShieldedAddress.fromPublicKeys(ShieldedPublicKey.fromEd25519(getAddressEncoder().encode(owner) as Bytes32),
      new Uint8Array(32).fill(1) as Bytes32, viewing.publicKey());
  } finally { viewing.destroy(); }
}
const registryAddress = shielded(recipient);
const fallbackAddress = shielded(recipient);
const [recordAddress, bump] = await getProgramDerivedAddress({
  programAddress: USER_REGISTRY_PROGRAM_ID,
  seeds: [new TextEncoder().encode("zolana/registry/v0"), getAddressEncoder().encode(recipient)],
});
const recordBytes = Uint8Array.of(
  1, ...getAddressEncoder().encode(recipient), bump,
  ...registryAddress.nullifierPublicKey, ...registryAddress.viewingPublicKey.toBytes(), 0,
);
const miss = { context: { slot: 10n }, value: null };
const registered = {
  context: { slot: 11n },
  value: {
    data: [Buffer.from(recordBytes).toString("base64"), "base64"] as const,
    owner: USER_REGISTRY_PROGRAM_ID,
    lamports: 1n,
  },
};
const service = { address: vi.fn(async () => fallbackAddress), genesisHash: genesisHashForNetwork("devnet") };
const genesis = vi.fn(async () => service.genesisHash);
const read = vi.fn<() => Promise<typeof miss | typeof registered>>();
const getAccountInfo = vi.fn(() => ({ send: read }));
const rpc = {
  commitment: "confirmed",
  solanaRpc: { getAccountInfo, getGenesisHash: () => ({ send: genesis }) },
} as unknown as Parameters<typeof resolvePaymentAddress>[0]["rpc"];
const request = { rpc, owner: recipient, service };

beforeEach(() => {
  read.mockReset().mockResolvedValue(miss);
  getAccountInfo.mockClear();
  genesis.mockReset().mockResolvedValue(service.genesisHash);
  service.address.mockReset().mockResolvedValue(fallbackAddress);
});

it("uses the registered address before asking the service", async () => {
  read.mockResolvedValue(registered);
  await expect(resolvePaymentAddress(request)).resolves.toEqual(registryAddress);
  expect(read).toHaveBeenCalledTimes(1);
  expect(getAccountInfo).toHaveBeenCalledWith(recordAddress, { commitment: "confirmed", encoding: "base64", minContextSlot: 0n });
  expect(service.address).not.toHaveBeenCalled();
  expect(genesis).toHaveBeenCalledOnce();
});

it("uses the service when both registry reads succeed with no record", async () => {
  await expect(resolvePaymentAddress(request)).resolves.toBe(fallbackAddress);
  expect(read).toHaveBeenCalledTimes(2);
  expect(getAccountInfo).toHaveBeenLastCalledWith(recordAddress, { commitment: "confirmed", encoding: "base64", minContextSlot: 10n });
  expect(service.address).toHaveBeenCalledWith(recipient, { signal: expect.any(AbortSignal) });
  expect(service.address).toHaveBeenCalledTimes(2);
  expect(service.address.mock.invocationCallOrder[1]).toBeGreaterThan(genesis.mock.invocationCallOrder[1]!);
});

it("uses a registration that appears during the service lookup", async () => {
  read.mockResolvedValueOnce(miss).mockResolvedValueOnce(registered);
  await expect(resolvePaymentAddress(request)).resolves.toEqual(registryAddress);
  expect(service.address).toHaveBeenCalledOnce();
  expect(read).toHaveBeenCalledTimes(2);
});

it.each([null, registered.value])("rejects a regressing registry response", async value => {
  read.mockResolvedValueOnce(miss).mockResolvedValueOnce({ context: { slot: 9n }, value });
  await expect(resolvePaymentAddress(request)).rejects.toMatchObject({
    cause: { code: "PaymentRegistryContextStale" },
  });
  expect(service.address).toHaveBeenCalledOnce();
});

it("refuses the service address if the second registry read fails", async () => {
  const failure = new Error("registry unavailable after service lookup");
  read.mockResolvedValueOnce(miss).mockRejectedValueOnce(failure);
  await expect(resolvePaymentAddress(request)).rejects.toMatchObject({ cause: failure });
  expect(service.address).toHaveBeenCalledOnce();
});

it("refuses the service address if the payment is cancelled during the second registry read", async () => {
  const controller = new AbortController();
  const reason = new Error("payment cancelled");
  read.mockResolvedValueOnce(miss).mockImplementationOnce(async () => {
    controller.abort(reason);
    return miss;
  });
  await expect(resolvePaymentAddress(request, { signal: controller.signal })).rejects.toBe(reason);
  expect(service.address).toHaveBeenCalledOnce();
});

it("propagates a registry failure without redirecting the payment", async () => {
  const failure = new Error("registry unavailable");
  read.mockRejectedValue(failure);
  await expect(resolvePaymentAddress(request)).rejects.toMatchObject({ cause: failure });
  expect(service.address).not.toHaveBeenCalled();
});

it("rejects a service address for another owner", async () => {
  const other = address("8NrtYowSfZ9AvdWf4GeTENbuGedACX4yTNxT1rAGnXWc");
  service.address.mockResolvedValueOnce(shielded(other));
  await expect(resolvePaymentAddress(request)).rejects.toThrow("ReleaseBindingMismatch");
});

it("does not fall back to the service after cancellation", async () => {
  const controller = new AbortController();
  read.mockImplementation(async () => {
    controller.abort(new Error("payment cancelled"));
    return miss;
  });
  await expect(resolvePaymentAddress(request, { signal: controller.signal })).rejects.toThrow("payment cancelled");
  expect(service.address).not.toHaveBeenCalled();
});

it("refuses another network or a malformed genesis before requesting recipient keys", async () => {
  for (const hash of [genesisHashForNetwork("mainnet"), "not-a-genesis"]) {
    genesis.mockResolvedValueOnce(hash);
    await expect(resolvePaymentAddress(request)).rejects.toMatchObject({ code: "PaymentNetworkMismatch" });
  }
  expect(service.address).not.toHaveBeenCalled();
});

it("propagates a failed genesis RPC without requesting recipient keys", async () => {
  const failure = new Error("genesis unavailable");
  genesis.mockRejectedValueOnce(failure);
  await expect(resolvePaymentAddress(request)).rejects.toBe(failure);
  expect(service.address).not.toHaveBeenCalled();
});

it.each(["first read", "after a miss"] as const)("rejects a registered address from the wrong chain at %s", async phase => {
  if (phase === "first read") {
    read.mockResolvedValueOnce(registered);
  } else {
    read.mockResolvedValueOnce(miss).mockResolvedValueOnce(registered);
    genesis.mockResolvedValueOnce(service.genesisHash);
  }
  genesis.mockResolvedValueOnce(genesisHashForNetwork("mainnet"));
  await expect(resolvePaymentAddress(request)).rejects.toMatchObject({ code: "PaymentNetworkMismatch" });
  expect(service.address).toHaveBeenCalledTimes(phase === "first read" ? 0 : 1);
});

it("refuses a fallback if the chain changes during the registry recheck", async () => {
  genesis.mockResolvedValueOnce(service.genesisHash).mockResolvedValueOnce(genesisHashForNetwork("mainnet"));
  await expect(resolvePaymentAddress(request)).rejects.toMatchObject({ code: "PaymentNetworkMismatch" });
  expect(service.address).toHaveBeenCalledOnce();
});

it("refuses a fallback when payment policy changes during the final chain check", async () => {
  const recoveryOnly = new Error("recovery only");
  genesis.mockResolvedValueOnce(service.genesisHash).mockImplementationOnce(async () => {
    service.address.mockRejectedValueOnce(recoveryOnly);
    return service.genesisHash;
  });
  await expect(resolvePaymentAddress(request)).rejects.toBe(recoveryOnly);
});

it("refuses a changed service address after the final chain check", async () => {
  service.address.mockResolvedValueOnce(fallbackAddress).mockResolvedValueOnce(registryAddress);
  await expect(resolvePaymentAddress(request)).rejects.toMatchObject({ code: "ReleaseBindingMismatch" });
});

it("refuses to attach local fixture keys to a public cluster", () => {
  for (const genesisHash of [genesisHashForNetwork("mainnet"), genesisHashForNetwork("devnet"), "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"]) {
    expect(() => createLocalDecryptionService({
      network: "devnet", endpoint: new URL("http://127.0.0.1/"), genesisHash,
    })).toThrow("PaymentNetworkMismatch");
  }
});

it("binds local fixture keys to the configured local validator", () => {
  const genesisHash = "11111111111111111111111111111111";
  const service = createLocalDecryptionService({
    network: "devnet", endpoint: new URL("http://127.0.0.1/"), genesisHash,
  });
  expect(service.genesisHash).toBe(genesisHash);
  expect(Object.isFrozen(service)).toBe(true);
});
