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

import { decodeLowerHex } from "../protocol/hex.js";
import type { DecryptItem } from "../protocol/types.js";
import { batched, decryptItem } from "../wallet/keys.js";

const TRANSACTION_KEY_LABEL = new TextEncoder().encode("TSPP/decryption-service/tx_key/v1");

/** Opens items with the service viewing key and returns one hex plaintext per item. */
type Decrypt = (items: readonly DecryptItem[], context?: RequestContext) => Promise<readonly string[]>;

/** The SDK's `WalletKeys` for an address under its service keys. */
export interface DecryptionServiceKeys extends WalletKeys {
  destroy(): void;
}

/** Delegates decryption to the service and derives transaction keys locally. */
export class ServiceKeys implements DecryptionServiceKeys {
  readonly #address: ShieldedAddress;
  readonly #local: LocalKeys;
  readonly #transactionKey: X25519PublicKey;
  readonly #decrypt: Decrypt;

  constructor(
    address: ShieldedAddress,
    nullifierSecret: Bytes31,
    proofs: ProofService,
    decrypt: Decrypt,
  ) {
    const nullifierKey = NullifierKey.fromSecret(nullifierSecret);
    const transactionKey = ViewingKey.fromBytes(
      hkdf(sha256, nullifierSecret, undefined, TRANSACTION_KEY_LABEL, 32) as Bytes32,
    );
    try {
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
      nullifierKey.destroy();
      transactionKey.destroy();
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
    const plaintexts = await batched(requests.map(decryptItem), (items) => this.#decrypt(items, context));
    return plaintexts.map(decodeLowerHex);
  }

  derive(requests: readonly DeriveRequest[]): Promise<readonly Bytes32[]> {
    return this.#local.derive(requests);
  }

  transactionKeys(requests: readonly TransactionKeyRequest[]): Promise<readonly ViewingKey[]> {
    return this.#local.transactionKeys(
      requests.map((request) => ({ ...request, viewingPublicKey: this.#transactionKey })),
    );
  }

  prove: LocalKeys["prove"] = (inputs, context) => this.#local.prove(inputs, context);
  proveMerge: LocalKeys["proveMerge"] = (inputs, context) => this.#local.proveMerge(inputs, context);
  proveIndexed: LocalKeys["proveIndexed"] = (request, context) => this.#local.proveIndexed(request, context);

  destroy(): void {
    this.#local.destroy();
  }
}
