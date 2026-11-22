import { ShieldedAddress, ShieldedPublicKey, type Bytes32, type ProofService } from "@heliuslabs/spr";
import type { Bytes31 } from "@heliuslabs/spr/keypair";
import { sha256 } from "@noble/hashes/sha256";
import { getAddressEncoder, type Address, type MessagePartialSigner } from "@solana/kit";

import type { BootProofResolver } from "../connection/backend.js";
import type { ConnectedTvcRuntime } from "../connection/connect.js";
import { requestScope, type DecryptionServiceRequestOptions } from "../connection/request.js";
import { createDecryptionServiceSession, type DecryptionServiceSession } from "../connection/session.js";
import type { DecryptionServiceTransport } from "../connection/http.js";
import { DecryptionServiceError, DecryptionServiceHttpError } from "../protocol/error.js";
import { bytesEqual, requireHex } from "../protocol/hex.js";
import { genesisHashForNetwork, requireNetwork } from "../protocol/network.js";
import { releaseForConnection, type ReleaseTrust } from "../protocol/releases.js";
import type { DecryptItem, Network } from "../protocol/types.js";
import { batched, checkPlaintexts } from "./items.js";
import { decodePublicKeys, executeServiceCall, type ServiceCall, type ServiceCallResult } from "./exchange.js";
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
  /** Full base58 Solana genesis hash bound to these service keys. */
  readonly genesisHash: string;
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
  genesisHash: string,
  { requestTimeoutMs, retryPublicKeys = false }: { requestTimeoutMs?: number | undefined; retryPublicKeys?: boolean } = {},
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
    forPayment = false,
  ): Promise<ServiceCallResult<T>> {
    let retry = retryPublicKeys && operation.type === "PublicKeys";
    for (;;) {
      let context: ConnectedTvcRuntime | undefined;
      try {
        context = await session.context(signal, forPayment);
        if (forPayment && context.recoveryOnly) {
          await context.requireCurrentCheckpoint?.(signal);
          throw new DecryptionServiceError("ReleasePolicyRecoveryOnly");
        }
        return await executeServiceCall(context, operation, signal);
      } catch (error) {
        const recoverable = context ? retryableExchangeFailure(error)
          : error instanceof DecryptionServiceError && error.code === "ReleasePolicySuperseded";
        if (context && (recoverable || (error instanceof DecryptionServiceHttpError && error.status !== 429))) {
          session.forget(context);
        }
        if (!retry || !recoverable) throw error;
        signal.throwIfAborted();
        retry = false;
      }
    }
  }

  async function address(owner: Address, signal: AbortSignal, forPayment: boolean): Promise<ShieldedAddress> {
    const { nullifierPublicKey, viewingPublicKey } = decodePublicKeys(
      await call({ type: "PublicKeys", address: owner }, signal, forPayment),
    );
    return ShieldedAddress.fromPublicKeys(
      ShieldedPublicKey.fromEd25519(new Uint8Array(addressEncoder.encode(owner)) as Bytes32),
      nullifierPublicKey,
      viewingPublicKey,
    );
  }

  async function decrypt(
    owner: MessagePartialSigner,
    items: readonly DecryptItem[],
    signal: AbortSignal,
  ) {
    const result = await call({ type: "Decrypt", owner, items }, signal);
    checkPlaintexts(result.plaintexts, items);
    return result;
  }

  return Object.freeze<DecryptionService>({
    genesisHash,
    address(owner, options) {
      return withinRequest(options, (signal) => address(owner, signal, true));
    },
    open(owner, proofs, options) {
      return withinRequest(options, async (signal) => {
        const signer = { address: owner.address, signMessages: owner.signMessages.bind(owner) };
        const shielded = await address(signer.address, signal, false);
        const bootstrap = await decrypt(signer, [], signal);
        signal.throwIfAborted();
        const nullifierSecret = requireHex(bootstrap.nullifier_secret, 31) as Bytes31;
        try {
          const nullifierDigest = sha256(nullifierSecret);
          return new ServiceKeys(shielded, nullifierSecret, proofs, (items, context) =>
            withinRequest(context, (batchSignal) =>
              batched(items, async (batch) => {
                const reply = await decrypt(signer, batch, batchSignal);
                const secret = requireHex(reply.nullifier_secret, 31);
                try {
                  if (!bytesEqual(sha256(secret), nullifierDigest)) {
                    throw new DecryptionServiceError("ReleaseBindingMismatch");
                  }
                  return reply.plaintexts;
                } finally {
                  secret.fill(0);
                }
              })),
          );
        } finally {
          nullifierSecret.fill(0);
        }
      });
    },
  });
}

function retryableExchangeFailure(error: unknown): boolean {
  // A restarted boot rejects requests sealed to the old key with a generic 400.
  if (error instanceof DecryptionServiceHttpError) return error.status === 400 || error.status === 408 || error.status >= 500;
  return error instanceof DecryptionServiceError && [
    "EndpointUnavailable", "BootProofUnverified", "ReleaseBindingMismatch", "ReleasePolicySuperseded",
  ].includes(error.code);
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
    genesisHashForNetwork(network),
    { requestTimeoutMs },
  );
}
