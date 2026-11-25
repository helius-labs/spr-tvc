import { ShieldedAddress, ShieldedPublicKey, type Bytes32 } from "@heliuslabs/spr";
import { X25519PublicKey, type Bytes31 } from "@heliuslabs/spr/keypair";
import { address as solanaAddress, createSignableMessage, getAddressEncoder, type Address, type MessagePartialSigner } from "@solana/kit";

import type { BootProofResolver } from "../connection/backend.js";
import { awaitWithSignal, requestScope, type DecryptionServiceRequestOptions } from "../connection/request.js";
import { createDecryptionServiceSession, type DecryptionServiceSession } from "../connection/session.js";
import type { DecryptionServiceTransport } from "../connection/http.js";
import { DecryptionServiceError, DecryptionServiceHttpError } from "../wire/error.js";
import { requireHex, decodeLowerHex, encodeLowerHex } from "../wire/hex.js";
import { requireNetwork } from "../wire/network.js";
import {
  acceptViewGrantWindow,
  viewGrantDigest,
  viewGrantMessage,
  viewGrantWire,
  type ViewGrant,
} from "../wire/decryption.js";
import { releaseForConnection, type ReleaseTrust } from "../wire/releases.js";
import type { DecryptItem, Network } from "../wire/types.js";
import { batched, checkHexList } from "./items.js";
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

/** Plaintexts in item order, plus the address's nullifier secret. The caller owns `nullifierSecret` and wipes it. */
type DecryptedNotes = {
  readonly plaintexts: readonly Uint8Array[];
  readonly nullifierSecret: Bytes31;
};

export type DecryptionService = {
  /** The shielded address a sender pays `owner` at before `owner` registers a wallet. */
  address(owner: Address, options?: DecryptionServiceRequestOptions): Promise<ShieldedAddress>;
  /**
   * Shielded keys for this service. `signer` is the owner, or a grantee named by `options.grant`.
   * Fetches the public keys only. The signer authorizes each later Decrypt, and the first one
   * also returns the nullifier secret.
   */
  keys(
    signer: MessagePartialSigner,
    options?: DecryptionServiceRequestOptions & { readonly grant?: ViewGrant },
  ): Promise<DecryptionServiceKeys>;
};

/** The owner signs a 30-minute view grant for `grantee` on this release. */
export async function signViewGrant(
  owner: MessagePartialSigner,
  input: {
    readonly grantee: Address;
    readonly network: Network;
    readonly quorumKeyId: string;
    readonly quorumKeyEpoch: bigint;
    readonly notBeforeMs: bigint;
    readonly expiryMs: bigint;
  },
  options?: DecryptionServiceRequestOptions,
): Promise<ViewGrant> {
  acceptViewGrantWindow(input.notBeforeMs, input.expiryMs, input.notBeforeMs);
  const unsigned = viewGrantWire({ ...input, owner: owner.address });
  const message = viewGrantMessage(
    new Uint8Array(addressEncoder.encode(owner.address)),
    viewGrantDigest(unsigned),
  );
  const scope = requestScope(options);
  try {
    const [signatures] = await awaitWithSignal(
      owner.signMessages([createSignableMessage(message)], { abortSignal: scope.signal }),
      scope.signal,
    );
    const signature = signatures?.[owner.address];
    if (signature?.length !== 64) throw new DecryptionServiceError("InvalidSignature");
    return { ...unsigned, signature: encodeLowerHex(signature) };
  } finally {
    scope.dispose();
  }
}

export function decryptionServiceFromSession(
  session: DecryptionServiceSession,
  requestTimeoutMs?: number,
): DecryptionService {
  async function withinRequest<T>(
    options: DecryptionServiceRequestOptions | undefined,
    run: (signal: AbortSignal) => Promise<T>,
  ): Promise<T> {
    const scope = requestScope(options, requestTimeoutMs);
    try {
      return await run(scope.signal);
    } finally {
      scope.dispose();
    }
  }

  async function call<T extends ServiceCall>(
    operation: T,
    signal: AbortSignal,
  ): Promise<ServiceCallResult<T>> {
    const context = await session.context(signal);
    try {
      return await executeServiceCall(context, operation, signal);
    } catch (error) {
      if (error instanceof DecryptionServiceHttpError) session.forget(context);
      throw error;
    }
  }

  async function address(owner: Address, signal: AbortSignal): Promise<ShieldedAddress> {
    const keys = await call({ type: "PublicKeys", address: owner }, signal);
    return ShieldedAddress.fromPublicKeys(
      ShieldedPublicKey.fromEd25519(new Uint8Array(addressEncoder.encode(owner)) as Bytes32),
      requireHex(keys.nullifier_public_key, 32) as Bytes32,
      X25519PublicKey.fromBytes(requireHex(keys.viewing_public_key, 33)),
    );
  }

  async function decryptItems(
    signer: MessagePartialSigner,
    items: readonly DecryptItem[],
    signal: AbortSignal,
    grant: ViewGrant | undefined,
  ): Promise<DecryptedNotes> {
    let secret: Bytes31 | undefined;
    try {
      const take = async (batch: readonly DecryptItem[]): Promise<readonly Uint8Array[]> => {
        const result = await call({
          type: "Decrypt",
          owner: signer,
          items: batch,
          ...(grant === undefined ? {} : { grant }),
        }, signal);
        checkHexList(result.plaintexts, batch.length);
        const next = requireHex(result.nullifier_secret, 31) as Bytes31;
        secret?.fill(0);
        secret = next;
        return result.plaintexts.map((plaintext) => decodeLowerHex(plaintext));
      };
      const plaintexts = items.length === 0 ? await take([]) : await batched(items, take);
      if (secret === undefined) throw new DecryptionServiceError("ReleaseBindingMismatch");
      const nullifierSecret = secret;
      secret = undefined;
      return { plaintexts, nullifierSecret };
    } finally {
      secret?.fill(0);
    }
  }

  return {
    address(owner, options) {
      return withinRequest(options, (signal) => address(owner, signal));
    },
    keys(signer, options) {
      return withinRequest(options, async (signal) => {
        const grant = options?.grant;
        const owner = grant === undefined ? signer.address : solanaAddress(grant.owner);
        const shielded = await address(owner, signal);
        return new ServiceKeys(shielded, (items, context) =>
          withinRequest(context, (batchSignal) => decryptItems(signer, items, batchSignal, grant)));
      });
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
    }),
    requestTimeoutMs,
  );
}
