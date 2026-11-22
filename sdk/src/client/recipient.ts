import { ShieldedAddress } from "@heliuslabs/spr";
import { resolveRegisteredAddress } from "@heliuslabs/spr/wallet";
import type { Address } from "@solana/kit";
import { awaitWithSignal, requestScope, type DecryptionServiceRequestOptions } from "../connection/request.js";
import { DecryptionServiceError } from "../protocol/error.js";
import type { DecryptionService } from "./decryption.js";

type AccountReader = Parameters<typeof resolveRegisteredAddress>[0]["rpc"];

/** Resolve the destination for this payment. Only an absent registry record uses the service. */
export async function resolvePaymentAddress(
  { rpc, owner, service }: Readonly<{ rpc: AccountReader; owner: Address; service: Pick<DecryptionService, "address"> }>,
  options?: DecryptionServiceRequestOptions,
): Promise<ShieldedAddress> {
  const { signal, dispose } = requestScope(options);
  try {
    signal.throwIfAborted();
    const registered = await awaitWithSignal(resolveRegisteredAddress({ rpc, owner }, { signal }), signal);
    if (registered) return registered.address;
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
