import { ShieldedAddress, ShieldedPublicKey, type Bytes32, type ProofService } from "@heliuslabs/spr";
import { X25519PublicKey, type Bytes31 } from "@heliuslabs/spr/keypair";
import { getAddressEncoder, type Address, type MessagePartialSigner } from "@solana/kit";

import type { BootProofResolver } from "../connection/backend.js";
import { requestScope, type DecryptionServiceRequestOptions } from "../connection/request.js";
import { createDecryptionServiceSession, type DecryptionServiceSession } from "../connection/session.js";
import type { DecryptionServiceTransport } from "../connection/http.js";
import { DecryptionServiceHttpError } from "../protocol/error.js";
import { requireHex } from "../protocol/hex.js";
import { requireNetwork } from "../protocol/network.js";
import { releaseForConnection, type ReleaseTrust } from "../protocol/releases.js";
import type { DecryptItem, Network } from "../protocol/types.js";
import { checkHexList, operationOptions } from "./items.js";
import { executeServiceCall, type ServiceCall, type ServiceCallResult } from "./exchange.js";
import { ServiceKeys, type DecryptionServiceKeys } from "./keys.js";
const addressEncoder = getAddressEncoder();

export type DecryptionServiceConfig = {
  readonly network: Network;
  /** Direct enclave URL or a relay that forwards its routes. */
  readonly endpoint: URL;
  /** Fetches a replica's Boot Proof from the decryption app's Turnkey organization. */
  readonly resolveBootProof: BootProofResolver;
  /** Mainnet uses only the policy from an override. The SDK pins its own trust anchors. */
  readonly release?: ReleaseTrust;
  /** Verifier clock override for development. Mainnet uses the system clock. */
  readonly nowMs?: () => bigint;
  readonly transport?: DecryptionServiceTransport;
  readonly requestTimeoutMs?: number;
};

export type DecryptionService = {
  /** The shielded address a sender pays `owner` at before `owner` registers a wallet. */
  address(owner: Address, options?: DecryptionServiceRequestOptions): Promise<ShieldedAddress>;
  /**
   * The keys of that address, for its owner. `owner` signs once here and once
   * for every batch of outputs a sync opens.
   */
  open(
    owner: MessagePartialSigner,
    proofs: ProofService,
    options?: DecryptionServiceRequestOptions,
  ): Promise<DecryptionServiceKeys>;
};

export function decryptionServiceFromSession(
  session: DecryptionServiceSession,
  requestTimeoutMs?: number,
): DecryptionService {
  async function call<T extends ServiceCall>(
    operation: T,
    options?: DecryptionServiceRequestOptions,
  ): Promise<ServiceCallResult<T>> {
    const scope = requestScope(options, requestTimeoutMs);
    try {
      const context = await session.context({ ...options, signal: scope.signal });
      try {
        return await executeServiceCall(context, operation, scope.signal);
      } catch (error) {
        // A refused or failed exchange may mean the release moved on.
        if (error instanceof DecryptionServiceHttpError && error.status !== 429) session.forget(context);
        throw error;
      }
    } finally {
      scope.dispose();
    }
  }

  async function address(owner: Address, options?: DecryptionServiceRequestOptions): Promise<ShieldedAddress> {
    const keys = await call({ type: "PublicKeys", address: owner }, options);
    return ShieldedAddress.fromPublicKeys(
      ShieldedPublicKey.fromEd25519(new Uint8Array(addressEncoder.encode(owner)) as Bytes32),
      requireHex(keys.nullifier_public_key, 32) as Bytes32,
      X25519PublicKey.fromBytes(requireHex(keys.viewing_public_key, 33)),
    );
  }

  async function decrypt(
    owner: MessagePartialSigner,
    items: readonly DecryptItem[],
    options?: DecryptionServiceRequestOptions,
  ) {
    const result = await call({ type: "Decrypt", owner, items }, options);
    checkHexList(result.plaintexts, items.length);
    return result;
  }

  return {
    address,
    async open(owner, proofs, options) {
      const shielded = await address(owner.address, options);
      const nullifierSecret = requireHex((await decrypt(owner, [], options)).nullifier_secret, 31) as Bytes31;
      try {
        return new ServiceKeys(shielded, nullifierSecret, proofs, async (items, context) =>
          (await decrypt(owner, items, operationOptions(context))).plaintexts);
      } finally {
        nullifierSecret.fill(0);
      }
    },
  };
}

/** A client of the decryption service at `config.endpoint`, verified against its release. */
export function createDecryptionService(config: DecryptionServiceConfig): DecryptionService {
  const network = requireNetwork(config.network);
  const { endpoint, resolveBootProof, nowMs, transport, requestTimeoutMs } = config;
  return decryptionServiceFromSession(
    createDecryptionServiceSession({
      network,
      backend: { endpoint, resolveBootProof },
      release: releaseForConnection(network, config.release),
      ...(network === "devnet" && nowMs !== undefined ? { nowMs } : {}),
      ...(transport === undefined ? {} : { transport }),
      ...(requestTimeoutMs === undefined ? {} : { requestTimeoutMs }),
    }),
    requestTimeoutMs,
  );
}
