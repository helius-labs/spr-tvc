import { NullifierKey, ShieldedAddress, ShieldedPublicKey, initializePoseidon, type Bytes32 } from "@heliuslabs/spr";
import { X25519Keypair, type Bytes31 } from "@heliuslabs/spr/keypair";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { decodeLowerHex, encodeLowerHex } from "../../src/wire/hex.js";
import type { DecryptItem } from "../../src/wire/types.js";
import { ServiceKeys, type OpenedNotes } from "../../src/client/keys.js";

const bytes = (fill: number, length = 32) => new Uint8Array(length).fill(fill);

beforeAll(() => initializePoseidon());

function opened(secret: Bytes31, items: readonly DecryptItem[]): OpenedNotes {
  return {
    plaintexts: items.map((item) => decodeLowerHex(item.ciphertext)),
    nullifierSecret: new Uint8Array(secret) as Bytes31,
  };
}

function keys(secret: Bytes31, decrypt = vi.fn(async (items: readonly DecryptItem[]) => opened(secret, items))) {
  const nullifier = NullifierKey.fromSecret(secret);
  const address = ShieldedAddress.fromPublicKeys(
    ShieldedPublicKey.fromEd25519(bytes(1) as Bytes32),
    nullifier.publicKey(),
    X25519Keypair.generate().publicKey(),
  );
  return { address, nullifier, decrypt, keys: new ServiceKeys(address, decrypt) };
}

describe("the keys of an address under the service", () => {
  it("are the service's address, with nullifiers from the secret the service returned", async () => {
    const { address, nullifier, keys: held } = keys(bytes(5, 31) as Bytes31);
    expect(held.address()).toBe(address);
    expect(held.viewingPublicKeys()).toEqual([address.viewingPublicKey]);
    const request = { kind: "nullifier", utxoHash: bytes(2) as Bytes32, blinding: bytes(3) as Bytes32 } as const;
    expect(await held.derive([request])).toEqual([nullifier.nullifier(request.utxoHash, request.blinding)]);
  });

  it("mint one transaction key per first nullifier, the same in every session", async () => {
    const mint = async (secret: number, first: number) => {
      const { address, keys: held } = keys(bytes(secret, 31) as Bytes31);
      const [key] = await held.transactionKeys([
        { viewingPublicKey: address.viewingPublicKey, firstNullifier: bytes(first) as Bytes32 },
      ]);
      return encodeLowerHex(key!.publicKey().toBytes());
    };
    expect(await mint(5, 1)).toBe(await mint(5, 1));
    expect(await mint(5, 1)).not.toBe(await mint(5, 2));
    expect(await mint(5, 1)).not.toBe(await mint(6, 1));
  });

  it("open outputs through the service, in order", async () => {
    const { address, decrypt, keys: held } = keys(bytes(5, 31) as Bytes31);
    const request = (fill: number) => ({
      ciphertext: bytes(fill, 50),
      viewingPublicKey: address.viewingPublicKey,
      txViewingPublicKey: X25519Keypair.generate().publicKey(),
      salt: bytes(0, 16) as never,
      slotIndex: fill,
      label: "transfer",
    } as const);
    expect(await held.decrypt([request(7), request(8)])).toEqual([bytes(7, 50), bytes(8, 50)]);
    expect(decrypt.mock.calls[0]?.[0].map((item) => item.slot_index)).toEqual(["7", "8"]);
    expect(await held.nullifierSecret()).toEqual(bytes(5, 31));
    expect(decrypt).toHaveBeenCalledOnce();
  });

  it("shares one decrypt when a derive starts beside the notes", async () => {
    const secret = bytes(5, 31) as Bytes31;
    const { address, nullifier, decrypt, keys: held } = keys(secret, vi.fn(async (items: readonly DecryptItem[]) => {
      await Promise.resolve();
      return opened(secret, items);
    }));
    const note = {
      ciphertext: bytes(7, 50),
      viewingPublicKey: address.viewingPublicKey,
      txViewingPublicKey: X25519Keypair.generate().publicKey(),
      salt: bytes(0, 16) as never,
      slotIndex: 7,
      label: "transfer",
    } as const;
    const derivation = { kind: "nullifier", utxoHash: bytes(2) as Bytes32, blinding: bytes(3) as Bytes32 } as const;
    const [nullifiers, openedNotes] = await Promise.all([
      held.derive([derivation]),
      held.decrypt([note]),
    ]);
    expect(openedNotes).toEqual([bytes(7, 50)]);
    expect(nullifiers).toEqual([nullifier.nullifier(derivation.utxoHash, derivation.blinding)]);
    expect(decrypt).toHaveBeenCalledOnce();
    expect(decrypt.mock.calls[0]?.[0]).toHaveLength(1);
  });
});
