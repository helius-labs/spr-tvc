import {
  NullifierKey,
  ShieldedAddress,
  ViewingKey,
  type Bytes32,
  type DecryptRequest,
  type DeriveRequest,
  type ProofService,
  type RequestContext,
  type WalletKeys,
} from "@heliuslabs/spr";
import { LocalKeys } from "@heliuslabs/spr/client";
import type { Bytes31, X25519PublicKey } from "@heliuslabs/spr/keypair";
import type { TransactionKeyRequest } from "@heliuslabs/spr/transaction";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

import { awaitWithSignal } from "../connection/request.js";
import { DecryptionServiceError } from "../protocol/error.js";
import { decodeLowerHex } from "../protocol/hex.js";
import type { DecryptItem } from "../protocol/types.js";
import { decryptItem } from "./items.js";

const TRANSACTION_KEY_LABEL = new TextEncoder().encode("TSPP/decryption-service/tx_key/v1");

/** Opens items with the service viewing key and returns one hex plaintext per item. */
type Decrypt = (items: readonly DecryptItem[], context?: RequestContext) => Promise<readonly string[]>;

/** The SDK's `WalletKeys` for an address under its service keys. */
export interface DecryptionServiceKeys extends WalletKeys {
  /** Cancels pending operations and wipes the locally held keys. */
  destroy(): void;
}

/** Delegates decryption to the service and derives transaction keys locally. */
export class ServiceKeys implements DecryptionServiceKeys {
  readonly #address: ShieldedAddress;
  readonly #local: LocalKeys;
  readonly #transactionKey: X25519PublicKey;
  readonly #decrypt: Decrypt;
  readonly #lifetime = new AbortController();

  constructor(
    address: ShieldedAddress,
    nullifierSecret: Bytes31,
    proofs: ProofService,
    decrypt: Decrypt,
  ) {
    const transactionBytes = hkdf(sha256, nullifierSecret, undefined, TRANSACTION_KEY_LABEL, 32) as Bytes32;
    let nullifierKey: NullifierKey | undefined;
    let transactionKey: ViewingKey | undefined;
    try {
      nullifierKey = NullifierKey.fromSecret(nullifierSecret);
      transactionKey = ViewingKey.fromBytes(transactionBytes);
      this.#transactionKey = transactionKey.publicKey();
      this.#local = LocalKeys.fromKeys({
        address: ShieldedAddress.fromPublicKeys(
          address.signingPublicKey,
          address.nullifierPublicKey,
          this.#transactionKey,
        ),
        viewingKeys: [transactionKey],
        nullifierKey,
      }, proofs);
    } finally {
      transactionBytes.fill(0);
      transactionKey?.destroy();
      nullifierKey?.destroy();
    }
    this.#address = address;
    this.#decrypt = decrypt;
  }

  address(): ShieldedAddress {
    return this.#address;
  }

  viewingPublicKeys(): readonly X25519PublicKey[] {
    return [this.#address.viewingPublicKey];
  }

  async decrypt(
    requests: readonly DecryptRequest[],
    context?: RequestContext,
  ): Promise<readonly Uint8Array[]> {
    const scope = this.#operationContext(context);
    const { signal } = scope;
    if (requests.length === 0) return [];
    const items = requests.map((request) => {
      this.#requireViewingKey(request.viewingPublicKey);
      return decryptItem(request);
    });
    const plaintexts = await awaitWithSignal(this.#decrypt(items, scope), signal);
    signal.throwIfAborted();
    return plaintexts.map(decodeLowerHex);
  }

  async derive(requests: readonly DeriveRequest[], context?: RequestContext): Promise<readonly Bytes32[]> {
    const { signal } = this.#operationContext(context);
    const answers = await this.#local.derive(requests);
    if (signal.aborted) {
      for (const answer of answers) answer.fill(0);
      signal.throwIfAborted();
    }
    return answers;
  }

  async transactionKeys(requests: readonly TransactionKeyRequest[], context?: RequestContext): Promise<readonly ViewingKey[]> {
    const { signal } = this.#operationContext(context);
    const keys = await this.#local.transactionKeys(
      requests.map((request) => {
        this.#requireViewingKey(request.viewingPublicKey);
        return { ...request, viewingPublicKey: this.#transactionKey };
      }),
    );
    if (signal.aborted) {
      for (const key of keys) key.destroy();
      signal.throwIfAborted();
    }
    return keys;
  }

  #requireViewingKey(key: X25519PublicKey): void {
    if (!this.#address.viewingPublicKey.equals(key)) throw new DecryptionServiceError("UnknownViewingKey");
  }

  prove: LocalKeys["prove"] = (inputs, context) => this.#proof(context, scope => this.#local.prove(inputs, scope));
  proveMerge: LocalKeys["proveMerge"] = (inputs, context) => this.#proof(context, scope => this.#local.proveMerge(inputs, scope));
  proveIndexed: LocalKeys["proveIndexed"] = (request, context) => this.#proof(context, scope => this.#local.proveIndexed(request, scope));

  async #proof<T>(context: RequestContext | undefined, run: (scope: RequestContext) => Promise<T>): Promise<T> {
    const scope = this.#operationContext(context);
    const result = await awaitWithSignal(run(scope), scope.signal);
    scope.signal.throwIfAborted();
    return result;
  }

  #operationContext(context?: RequestContext): RequestContext & { signal: AbortSignal } {
    const lifetime = this.#lifetime.signal;
    const signal = context?.signal ? AbortSignal.any([lifetime, context.signal]) : lifetime;
    signal.throwIfAborted();
    return { ...context, signal };
  }

  destroy(): void {
    this.#lifetime.abort(new DecryptionServiceError("KeyHandleDestroyed"));
    this.#local.destroy();
  }
}
