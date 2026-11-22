import { ShieldedAddress, ShieldedPublicKey, ViewingKey, type Bytes32 } from "@heliuslabs/spr";
import { resolveRegisteredAddress } from "@heliuslabs/spr/wallet";
import { address, getAddressEncoder, type Address } from "@solana/kit";
import { beforeEach, expect, it, vi } from "vitest";
import { createLocalDecryptionService } from "../../src/testing.js";
import { genesisHashForNetwork } from "../../src/protocol/network.js";
import { resolvePaymentAddress } from "../../src/client/recipient.js";

vi.mock("@heliuslabs/spr/wallet", () => ({ resolveRegisteredAddress: vi.fn() }));

const lookup = vi.mocked(resolveRegisteredAddress);
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
const registered = { address: registryAddress } as NonNullable<Awaited<ReturnType<typeof lookup>>>;
const service = { address: vi.fn(async () => fallbackAddress), genesisHash: genesisHashForNetwork("devnet") };
const genesis = vi.fn(async () => service.genesisHash);
const rpc = { getAccount: vi.fn(), solanaRpc: { getGenesisHash: () => ({ send: genesis }) } };
const request = { rpc, owner: recipient, service };

beforeEach(() => {
  lookup.mockReset();
  vi.clearAllMocks();
});

it("uses the registered address before asking the service", async () => {
  lookup.mockResolvedValue(registered);
  await expect(resolvePaymentAddress(request)).resolves.toBe(registryAddress);
  expect(lookup).toHaveBeenCalledTimes(1);
  expect(lookup).toHaveBeenCalledWith({ rpc, owner: recipient }, { signal: expect.any(AbortSignal) });
  expect(service.address).not.toHaveBeenCalled();
  expect(genesis).not.toHaveBeenCalled();
});

it("uses the service when both registry reads succeed with no record", async () => {
  lookup.mockResolvedValue(undefined);
  await expect(resolvePaymentAddress(request)).resolves.toBe(fallbackAddress);
  expect(lookup).toHaveBeenCalledTimes(2);
  expect(lookup.mock.calls[1]).toEqual(lookup.mock.calls[0]);
  expect(service.address).toHaveBeenCalledWith(recipient, lookup.mock.calls[0]?.[1]);
});

it("uses a registration that appears during the service lookup", async () => {
  lookup.mockResolvedValueOnce(undefined).mockResolvedValueOnce(registered);
  await expect(resolvePaymentAddress(request)).resolves.toBe(registryAddress);
  expect(service.address).toHaveBeenCalledOnce();
  expect(lookup).toHaveBeenCalledTimes(2);
});

it("refuses the service address if the second registry read fails", async () => {
  const failure = new Error("registry unavailable after service lookup");
  lookup.mockResolvedValueOnce(undefined).mockRejectedValueOnce(failure);
  await expect(resolvePaymentAddress(request)).rejects.toBe(failure);
  expect(service.address).toHaveBeenCalledOnce();
});

it("refuses the service address if the payment is cancelled during the second registry read", async () => {
  const controller = new AbortController();
  const reason = new Error("payment cancelled");
  lookup.mockResolvedValueOnce(undefined).mockImplementationOnce(async () => {
    controller.abort(reason);
    return undefined;
  });
  await expect(resolvePaymentAddress(request, { signal: controller.signal })).rejects.toBe(reason);
  expect(service.address).toHaveBeenCalledOnce();
});

it("propagates a registry failure without redirecting the payment", async () => {
  const failure = new Error("registry unavailable");
  lookup.mockRejectedValue(failure);
  await expect(resolvePaymentAddress(request)).rejects.toBe(failure);
  expect(service.address).not.toHaveBeenCalled();
});

it("rejects a service address for another owner", async () => {
  const other = address("8NrtYowSfZ9AvdWf4GeTENbuGedACX4yTNxT1rAGnXWc");
  lookup.mockResolvedValue(undefined);
  service.address.mockResolvedValueOnce(shielded(other));
  await expect(resolvePaymentAddress(request)).rejects.toThrow("ReleaseBindingMismatch");
});

it("does not fall back to the service after cancellation", async () => {
  const controller = new AbortController();
  lookup.mockImplementation(async () => {
    controller.abort(new Error("payment cancelled"));
    return undefined;
  });
  await expect(resolvePaymentAddress(request, { signal: controller.signal })).rejects.toThrow("payment cancelled");
  expect(service.address).not.toHaveBeenCalled();
});

it("refuses another network or a malformed genesis before requesting recipient keys", async () => {
  lookup.mockResolvedValue(undefined);
  for (const hash of [genesisHashForNetwork("mainnet"), "not-a-genesis"]) {
    genesis.mockResolvedValueOnce(hash);
    await expect(resolvePaymentAddress(request)).rejects.toMatchObject({ code: "PaymentNetworkMismatch" });
  }
  expect(service.address).not.toHaveBeenCalled();
});

it("propagates a failed genesis RPC without requesting recipient keys", async () => {
  lookup.mockResolvedValue(undefined);
  const failure = new Error("genesis unavailable");
  genesis.mockRejectedValueOnce(failure);
  await expect(resolvePaymentAddress(request)).rejects.toBe(failure);
  expect(service.address).not.toHaveBeenCalled();
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
