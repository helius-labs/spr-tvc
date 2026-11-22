import { ShieldedAddress, ShieldedPublicKey, ViewingKey, type Bytes32 } from "@heliuslabs/spr";
import { resolveRegisteredAddress } from "@heliuslabs/spr/wallet";
import { address, getAddressEncoder, type Address } from "@solana/kit";
import { beforeEach, expect, it, vi } from "vitest";
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
const service = { address: vi.fn(async () => fallbackAddress) };
const rpc = { getAccount: vi.fn() };
const request = { rpc, owner: recipient, service };

beforeEach(() => vi.clearAllMocks());

it("uses the registered address before asking the service", async () => {
  lookup.mockResolvedValue({ address: registryAddress } as NonNullable<Awaited<ReturnType<typeof lookup>>>);
  await expect(resolvePaymentAddress(request)).resolves.toBe(registryAddress);
  expect(lookup).toHaveBeenCalledWith({ rpc, owner: recipient }, { signal: expect.any(AbortSignal) });
  expect(service.address).not.toHaveBeenCalled();
});

it("uses the service only when the registry lookup succeeds with no record", async () => {
  lookup.mockResolvedValue(undefined);
  await expect(resolvePaymentAddress(request)).resolves.toBe(fallbackAddress);
  expect(service.address).toHaveBeenCalledWith(recipient, lookup.mock.calls[0]?.[1]);
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
