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

import { awaitWithSignal } from "../connection/request.js";
import { SHA256_LEN } from "../wire/constants.js";
import { DecryptionServiceError } from "../wire/error.js";
import type { DecryptItem } from "../wire/types.js";
import { decryptItem } from "./items.js";

const TRANSACTION_KEY_LABEL = new TextEncoder().encode("TSPP/decryption-service/tx_key/v1");

/** One plaintext per item, plus the address's nullifier secret. The keys wipe `nullifierSecret`. */
export type OpenedNotes = {
  readonly plaintexts: readonly Uint8Array[];
  readonly nullifierSecret: Bytes31;
};

/** Opens items with the service viewing key. An empty list still returns the nullifier secret. */
type Decrypt = (items: readonly DecryptItem[], context?: RequestContext) => Promise<OpenedNotes>;

/** Shielded keys whose notes the decryption service opens. A spend uses the nullifier secret with the SPR prover. */
export interface DecryptionServiceKeys extends ShieldedKeys {
  /**
   * A copy of the nullifier secret. The caller wipes it.
   * The first note decrypt supplies it. A spend that has not opened notes fetches it once.
   */
  nullifierSecret(): Promise<Bytes31>;
  destroy(): void;
}

/**
 * Delegates decryption to the service and derives from the nullifier secret locally.
 * The secret arrives with the first Decrypt. A concurrent derive waits for that call
 * instead of sending an empty batch of its own.
 */
export class ServiceKeys implements DecryptionServiceKeys {
  readonly #address: ShieldedAddress;
  readonly #decrypt: Decrypt;
  #local: LocalShieldedKeys | undefined;
  #transactionKey: X25519PublicKey | undefined;
  #opening: Promise<void> | undefined;
  #destroyed = false;

  constructor(address: ShieldedAddress, decrypt: Decrypt) {
    this.#address = address;
    this.#decrypt = decrypt;
  }

  address(): ShieldedAddress {
    return this.#address;
  }

  viewingPublicKeys(): readonly X25519PublicKey[] {
    return [this.#address.viewingPublicKey];
  }

  async nullifierSecret(): Promise<Bytes31> {
    const local = await this.#ready();
    return local.withNullifierKey((key) => key.secretBytes());
  }

  decrypt(requests: readonly DecryptRequest[], context?: RequestContext): Promise<readonly Uint8Array[]> {
    this.#checkLive();
    if (requests.length === 0) return Promise.resolve([]);
    const job = this.#decrypt(requests.map(decryptItem), context);
    const ownsSecret = this.#local === undefined && this.#opening === undefined;
    if (ownsSecret) this.#claim(job);
    return job.then((opened) => {
      if (!ownsSecret) opened.nullifierSecret.fill(0);
      return opened.plaintexts;
    });
  }

  async derive(requests: readonly DeriveRequest[], context?: RequestContext): Promise<readonly Bytes32[]> {
    const local = await this.#ready(context);
    return local.derive(requests);
  }

  async transactionKeys(
    requests: readonly TransactionKeyRequest[],
    context?: RequestContext,
  ): Promise<readonly ViewingKey[]> {
    const local = await this.#ready(context);
    const transactionKey = this.#transactionKey;
    if (transactionKey === undefined) throw new DecryptionServiceError("ReleaseBindingMismatch");
    return local.transactionKeys(
      requests.map((request) => ({ ...request, viewingPublicKey: transactionKey })),
    );
  }

  destroy(): void {
    this.#destroyed = true;
    this.#local?.destroy();
    this.#local = undefined;
    this.#transactionKey = undefined;
  }

  #claim(job: Promise<OpenedNotes>): void {
    const ready = job.then((opened) => {
      this.#install(opened.nullifierSecret);
    });
    this.#opening = ready;
    void ready.catch(() => {
      if (this.#opening === ready) this.#opening = undefined;
    });
  }

  async #ready(context?: RequestContext): Promise<LocalShieldedKeys> {
    this.#checkLive();
    if (this.#local !== undefined) return this.#local;
    if (this.#opening === undefined) {
      // A note decrypt started in this turn claims the secret. Wait for it
      // before sending an empty batch.
      await Promise.resolve();
      this.#checkLive();
      if (this.#local === undefined && this.#opening === undefined) {
        this.#claim(this.#decrypt([], context));
      }
    }
    const opening = this.#opening;
    if (opening === undefined) throw new DecryptionServiceError("ReleaseBindingMismatch");
    await awaitWithSignal(opening, context?.signal);
    this.#checkLive();
    if (this.#local === undefined) throw new DecryptionServiceError("ReleaseBindingMismatch");
    return this.#local;
  }

  #install(secret: Bytes31): void {
    if (this.#destroyed || this.#local !== undefined) {
      secret.fill(0);
      return;
    }
    const nullifierKey = NullifierKey.fromSecret(secret);
    const transactionSeed = hkdf(sha256, secret, undefined, TRANSACTION_KEY_LABEL, SHA256_LEN) as Bytes32;
    let transactionKey: ViewingKey | undefined;
    try {
      transactionKey = ViewingKey.fromBytes(transactionSeed);
      const transactionPublic = transactionKey.publicKey();
      this.#local = LocalShieldedKeys.fromKeys({
        address: ShieldedAddress.fromPublicKeys(
          this.#address.signingPublicKey,
          this.#address.nullifierPublicKey,
          transactionPublic,
        ),
        viewingKeys: [transactionKey],
        nullifierKey,
      });
      this.#transactionKey = transactionPublic;
    } finally {
      nullifierKey.destroy();
      transactionKey?.destroy();
      transactionSeed.fill(0);
      secret.fill(0);
    }
  }

  #checkLive(): void {
    if (this.#destroyed) throw new Error("decryption service keys are destroyed");
  }
}
