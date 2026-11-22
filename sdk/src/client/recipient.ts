import { ShieldedAddress } from "@heliuslabs/spr";
import { resolveRegisteredAddress } from "@heliuslabs/spr/wallet";
import { isAddress, type Address } from "@solana/kit";
import { awaitWithSignal, requestScope, type DecryptionServiceRequestOptions } from "../connection/request.js";
import { DecryptionServiceError } from "../protocol/error.js";
import type { DecryptionService } from "./decryption.js";

type PaymentRpc = Parameters<typeof resolveRegisteredAddress>[0]["rpc"] & {
  readonly solanaRpc: {
    getGenesisHash(): { send(options: { abortSignal: AbortSignal }): Promise<string> };
  };
};

/** Resolve the destination for this payment. Only an absent registry record uses the service. */
export async function resolvePaymentAddress(
  { rpc, owner, service }: Readonly<{ rpc: PaymentRpc; owner: Address; service: Pick<DecryptionService, "address" | "genesisHash"> }>,
  options?: DecryptionServiceRequestOptions,
): Promise<ShieldedAddress> {
  const { signal, dispose } = requestScope(options);
  try {
    signal.throwIfAborted();
    const registered = await awaitWithSignal(resolveRegisteredAddress({ rpc, owner }, { signal }), signal);
    if (registered) return registered.address;
    signal.throwIfAborted();
    const genesisHash = await awaitWithSignal(rpc.solanaRpc.getGenesisHash().send({ abortSignal: signal }), signal);
    if (!isAddress(genesisHash) || genesisHash !== service.genesisHash) {
      throw new DecryptionServiceError("PaymentNetworkMismatch");
    }
    signal.throwIfAborted();
    const fallback = await awaitWithSignal(service.address(owner, { signal }), signal);
    if (!(fallback instanceof ShieldedAddress) || fallback.signingPublicKey.signatureType() !== "ed25519" ||
        fallback.solanaAddress() !== owner) {
      throw new DecryptionServiceError("ReleaseBindingMismatch", "payment address does not match its owner");
    }
    return fallback;
  } finally {
    dispose();
  }
}
