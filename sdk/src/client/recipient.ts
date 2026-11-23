import { ShieldedAddress } from "@heliuslabs/spr";
import { resolveRegisteredAddress } from "@heliuslabs/spr/wallet";
import { getBase64Encoder, isAddress, type Address, type Commitment, type Rpc, type SolanaRpcApi } from "@solana/kit";
import { awaitWithSignal, requestScope, type DecryptionServiceRequestOptions } from "../connection/request.js";
import { DecryptionServiceError } from "../protocol/error.js";
import { bytesEqual } from "../protocol/hex.js";
import type { DecryptionService } from "./decryption.js";

type PaymentRpc = {
  readonly commitment: Commitment;
  readonly solanaRpc: Pick<Rpc<SolanaRpcApi>, "getAccountInfo" | "getGenesisHash">;
};

/** Prefer the registry record, including one observed after the service lookup. */
export async function resolvePaymentAddress(
  { rpc, owner, service }: Readonly<{ rpc: PaymentRpc; owner: Address; service: Pick<DecryptionService, "address" | "genesisHash"> }>,
  options?: DecryptionServiceRequestOptions,
): Promise<ShieldedAddress> {
  const { signal, dispose } = requestScope(options);
  try {
    let slotFloor = 0n;
    const registry: Parameters<typeof resolveRegisteredAddress>[0]["rpc"] = {
      async getAccount(address) {
        signal.throwIfAborted();
        const result = await awaitWithSignal(rpc.solanaRpc.getAccountInfo(address, {
          commitment: rpc.commitment, encoding: "base64", minContextSlot: slotFloor,
        }).send({ abortSignal: signal }), signal);
        const slot = result?.context?.slot;
        if (typeof slot !== "bigint" || slot < slotFloor || slot > 0xffff_ffff_ffff_ffffn) {
          throw new DecryptionServiceError("PaymentRegistryContextStale");
        }
        slotFloor = slot;
        const { value } = result;
        if (value === null) return undefined;
        if (!isAddress(value?.owner) || typeof value.lamports !== "bigint" || value.lamports < 0n ||
            value.lamports > 0xffff_ffff_ffff_ffffn || !Array.isArray(value.data) ||
            value.data.length !== 2 || value.data[1] !== "base64" || typeof value.data[0] !== "string") {
          throw new DecryptionServiceError("PaymentRegistryAccountInvalid");
        }
        return {
          owner: value.owner,
          lamports: value.lamports,
          data: new Uint8Array(getBase64Encoder().encode(value.data[0])),
        };
      },
    };
    const lookup = () => awaitWithSignal(resolveRegisteredAddress({ rpc: registry, owner }, { signal }), signal);
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
    await requireServiceChain();
    if (registered) return registered.address;
    const fallback = await serviceAddress();
    const latestRegistration = await lookup();
    await requireServiceChain();
    if (latestRegistration) return latestRegistration.address;
    const confirmed = await serviceAddress();
    if (!bytesEqual(confirmed.toBytes(), fallback.toBytes())) {
      throw new DecryptionServiceError("ReleaseBindingMismatch", "service payment address changed during lookup");
    }
    return confirmed;
  } finally {
    dispose();
  }
}
