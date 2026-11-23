import { ShieldedAddress } from "@heliuslabs/spr";
import { resolveRegisteredAddress } from "@heliuslabs/spr/wallet";
import { isAddress, type Address } from "@solana/kit";
import { awaitWithSignal, requestScope, type DecryptionServiceRequestOptions } from "../connection/request.js";
import { DecryptionServiceError } from "../protocol/error.js";
import { bytesEqual } from "../protocol/hex.js";
import type { DecryptionService } from "./decryption.js";

type PaymentRpc = Parameters<typeof resolveRegisteredAddress>[0]["rpc"] & {
  readonly solanaRpc: {
    getGenesisHash(): { send(options: { abortSignal: AbortSignal }): Promise<string> };
  };
};

/** Prefer the registry record, including one observed after the service lookup. */
export async function resolvePaymentAddress(
  { rpc, owner, service }: Readonly<{ rpc: PaymentRpc; owner: Address; service: Pick<DecryptionService, "address" | "genesisHash"> }>,
  options?: DecryptionServiceRequestOptions,
): Promise<ShieldedAddress> {
  const { signal, dispose } = requestScope(options);
  try {
    const lookup = () => awaitWithSignal(resolveRegisteredAddress({ rpc, owner }, { signal }), signal);
    async function requireServiceChain() {
      signal.throwIfAborted();
      const genesisHash = await awaitWithSignal(rpc.solanaRpc.getGenesisHash().send({ abortSignal: signal }), signal);
      if (!isAddress(genesisHash) || genesisHash !== service.genesisHash) {
        throw new DecryptionServiceError("PaymentNetworkMismatch");
      }
    }
    async function serviceAddress() {
      signal.throwIfAborted();
      const address = await awaitWithSignal(service.address(owner, { signal }), signal);
      if (!(address instanceof ShieldedAddress) || address.signingPublicKey.signatureType() !== "ed25519" ||
          address.solanaAddress() !== owner) {
        throw new DecryptionServiceError("ReleaseBindingMismatch", "payment address does not match its owner");
      }
      return address;
    }
    signal.throwIfAborted();
    const registered = await lookup();
    if (registered) return registered.address;
    await requireServiceChain();
    const fallback = await serviceAddress();
    const latestRegistration = await lookup();
    if (latestRegistration) return latestRegistration.address;
    await requireServiceChain();
    const confirmed = await serviceAddress();
    if (!bytesEqual(confirmed.toBytes(), fallback.toBytes())) {
      throw new DecryptionServiceError("ReleaseBindingMismatch", "service payment address changed during lookup");
    }
    return confirmed;
  } finally {
    dispose();
  }
}
