import {
  LocalShieldedKeys,
  NullifierKey,
  ShieldedAddress,
  ViewingKey,
  type Bytes32,
  type DecryptRequest,
  type DeriveRequest,
  type RequestContext,
  type ShieldedKeys,
} from "@heliuslabs/spr";
import type { Bytes31, X25519PublicKey } from "@heliuslabs/spr/keypair";
import type { TransactionKeyRequest } from "@heliuslabs/spr/transaction";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

import type { DecryptItem } from "../protocol/types.js";
import { decryptItem } from "./items.js";

const TRANSACTION_KEY_LABEL = new TextEncoder().encode("TSPP/decryption-service/tx_key/v1");

/** Opens items with the service viewing key and returns one plaintext per item. */
type Decrypt = (items: readonly DecryptItem[], context?: RequestContext) => Promise<readonly Uint8Array[]>;

/** Shielded keys whose notes the decryption service opens. A spend uses the nullifier secret with the SPR prover. */
export interface DecryptionServiceKeys extends ShieldedKeys {
  /** A copy of the nullifier secret. The caller wipes it. */
  nullifierSecret(): Bytes31;
  destroy(): void;
}

/** Delegates decryption to the service and derives from the nullifier secret locally. */
export class ServiceKeys implements DecryptionServiceKeys {
  readonly #address: ShieldedAddress;
  readonly #local: LocalShieldedKeys;
  readonly #transactionKey: X25519PublicKey;
  readonly #decrypt: Decrypt;

  constructor(address: ShieldedAddress, nullifierSecret: Bytes31, decrypt: Decrypt) {
    const nullifierKey = NullifierKey.fromSecret(nullifierSecret);
    const transactionKey = ViewingKey.fromBytes(
      hkdf(sha256, nullifierSecret, undefined, TRANSACTION_KEY_LABEL, 32) as Bytes32,
    );
    try {
      this.#transactionKey = transactionKey.publicKey();
      this.#local = LocalShieldedKeys.fromKeys({
        address: ShieldedAddress.fromPublicKeys(
          address.signingPublicKey,
          address.nullifierPublicKey,
          this.#transactionKey,
        ),
        viewingKeys: [transactionKey],
        nullifierKey,
      });
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

  nullifierSecret(): Bytes31 {
    return this.#local.withNullifierKey((key) => key.secretBytes());
  }

  decrypt(requests: readonly DecryptRequest[], context?: RequestContext): Promise<readonly Uint8Array[]> {
    if (requests.length === 0) return Promise.resolve([]);
    return this.#decrypt(requests.map(decryptItem), context);
  }

  derive(requests: readonly DeriveRequest[], _context?: RequestContext): Promise<readonly Bytes32[]> {
    return this.#local.derive(requests);
  }

  transactionKeys(
    requests: readonly TransactionKeyRequest[],
    _context?: RequestContext,
  ): Promise<readonly ViewingKey[]> {
    return this.#local.transactionKeys(
      requests.map((request) => ({ ...request, viewingPublicKey: this.#transactionKey })),
    );
  }

  destroy(): void {
    this.#local.destroy();
  }
}
