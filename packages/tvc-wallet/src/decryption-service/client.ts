import { ShieldedAddress, ShieldedPublicKey, type Bytes32, type ProofService } from "@heliuslabs/spr";
import { X25519PublicKey, type Bytes31 } from "@heliuslabs/spr/keypair";
import { getAddressEncoder, type Address, type MessagePartialSigner } from "@solana/kit";

import type { BootProofResolver, SprEmbeddedWalletBackend } from "../client/backend.js";
import { requestScope, type SprEmbeddedWalletRequestOptions } from "../client/request.js";
import { createSprEmbeddedWalletSession, type SprEmbeddedWalletSession } from "../client/session.js";
import type { SprEmbeddedWalletTransport } from "../client/transport.js";
import { SprEmbeddedWalletHttpError } from "../protocol/error.js";
import { requireHex } from "../protocol/hex.js";
import { requireNetwork } from "../protocol/network.js";
import { pinnedReleases, releaseFor, type ReleaseTrust } from "../protocol/releases.js";
import type { DecryptItem, Network } from "../protocol/types.js";
import { operationOptions } from "../wallet/keys.js";
import { checkHexList } from "../wallet/operations.js";
import { executeServiceCall, type ServiceCall, type ServiceCallResult } from "./exchange.js";
import { ServiceKeys, type DecryptionServiceKeys } from "./keys.js";
import { SERVICE_PROOF_TYPE } from "./protocol.js";
import devnet from "./releases/devnet.json";
import mainnet from "./releases/mainnet.json";

const addressEncoder = getAddressEncoder();

/** The live decryption-service release of each network that has one. */
export const DECRYPTION_SERVICE_RELEASES = pinnedReleases({ devnet, mainnet });

export type DecryptionServiceConfig = {
  readonly network: Network;
  /**
   * The enclave's public ingress, or a tvc-gateway's `/v1/decryption` (with any
   * query such as gatekeeper's `api-key`). Without `resolveBootProof` the
   * client treats `endpoint` as a gateway and reads Boot Proofs beside session
   * and operation answers.
   */
  readonly endpoint: URL;
  /**
   * Fetches a replica's Boot Proof when talking to the enclave directly, such
   * as with an authenticated Turnkey session. Omit for a gateway endpoint.
   */
  readonly resolveBootProof?: BootProofResolver;
  /** The release to verify against; the package's pin for `network` by default. */
  readonly release?: ReleaseTrust;
  readonly nowMs?: () => bigint;
  readonly transport?: SprEmbeddedWalletTransport;
  readonly requestTimeoutMs?: number;
};

export type DecryptionService = {
  /** The shielded address a sender pays `owner` at before `owner` registers a wallet. */
  address(owner: Address, options?: SprEmbeddedWalletRequestOptions): Promise<ShieldedAddress>;
  /**
   * The keys of that address, for its owner. `owner` signs once here and once
   * for every batch of outputs a sync opens.
   */
  open(
    owner: MessagePartialSigner,
    proofs: ProofService,
    options?: SprEmbeddedWalletRequestOptions,
  ): Promise<DecryptionServiceKeys>;
};

export function decryptionServiceFromSession(
  session: SprEmbeddedWalletSession,
  requestTimeoutMs?: number,
): DecryptionService {
  async function call<T extends ServiceCall>(
    operation: T,
    options?: SprEmbeddedWalletRequestOptions,
  ): Promise<ServiceCallResult<T>> {
    const scope = requestScope(options, requestTimeoutMs);
    try {
      const context = await session.context({ ...options, signal: scope.signal });
      try {
        return await executeServiceCall(context, operation, scope.signal);
      } catch (error) {
        // A refused or failed exchange may mean the release moved on.
        if (error instanceof SprEmbeddedWalletHttpError && error.status !== 429) session.forget(context);
        throw error;
      }
    } finally {
      scope.dispose();
    }
  }

  async function address(owner: Address, options?: SprEmbeddedWalletRequestOptions): Promise<ShieldedAddress> {
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
    options?: SprEmbeddedWalletRequestOptions,
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

/** Direct enclave or gateway backend for `createDecryptionService`. */
function decryptionBackend(
  endpoint: URL,
  resolveBootProof: BootProofResolver | undefined,
): SprEmbeddedWalletBackend {
  if (resolveBootProof) {
    return { kind: "enclave", endpoint, resolveBootProof };
  }
  return { kind: "gateway", endpoint, decryptionService: true };
}

/** A client of the decryption service at `config.endpoint`, verified against its release. */
export function createDecryptionService(config: DecryptionServiceConfig): DecryptionService {
  const network = requireNetwork(config.network);
  const { endpoint, resolveBootProof, nowMs, transport, requestTimeoutMs } = config;
  return decryptionServiceFromSession(
    createSprEmbeddedWalletSession({
      network,
      backend: decryptionBackend(endpoint, resolveBootProof),
      release: config.release ?? releaseFor(network, DECRYPTION_SERVICE_RELEASES),
      proofType: SERVICE_PROOF_TYPE,
      ...(nowMs === undefined ? {} : { nowMs }),
      ...(transport === undefined ? {} : { transport }),
      ...(requestTimeoutMs === undefined ? {} : { requestTimeoutMs }),
    }),
    requestTimeoutMs,
  );
}
