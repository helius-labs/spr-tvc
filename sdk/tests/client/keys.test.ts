import { NullifierKey, ShieldedAddress, ShieldedPublicKey, ViewingKey, initializePoseidon, type Bytes32, type RequestContext } from "@heliuslabs/spr";
import { X25519Keypair, X25519PublicKey, type Bytes31 } from "@heliuslabs/spr/keypair";
import { LocalKeys } from "@heliuslabs/spr/client";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { encodeLowerHex } from "../../src/protocol/hex.js";
import type { DecryptItem } from "../../src/protocol/types.js";
import { ServiceKeys } from "../../src/client/keys.js";

const proofs = { prove: vi.fn(), proveMerge: vi.fn() };
const bytes = (fill: number, length = 32) => new Uint8Array(length).fill(fill);

beforeAll(() => initializePoseidon());

function keys(secret: Bytes31, decrypt = vi.fn(async (items: readonly DecryptItem[], _context?: RequestContext) =>
  items.map((item) => item.ciphertext))) {
  const nullifier = NullifierKey.fromSecret(secret);
  const address = ShieldedAddress.fromPublicKeys(
    ShieldedPublicKey.fromEd25519(bytes(1) as Bytes32),
    nullifier.publicKey(),
    X25519Keypair.generate().publicKey(),
  );
  return { address, nullifier, decrypt, keys: new ServiceKeys(address, secret, proofs, decrypt) };
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

  it("clears the transaction key derivation buffer on success and when the identity fails", () => {
    const fromBytes = vi.spyOn(ViewingKey, "fromBytes");
    const { address, nullifier, decrypt, keys: held } = keys(bytes(5, 31) as Bytes31);
    try {
      expect(fromBytes.mock.calls[0]?.[0]).toEqual(bytes(0));
      fromBytes.mockClear();
      expect(() => new ServiceKeys(address, bytes(6, 31) as Bytes31, proofs, decrypt))
        .toThrow(/IDENTITY_MISMATCH/);
      expect(fromBytes.mock.calls[0]?.[0]).toEqual(bytes(0));
    } finally {
      fromBytes.mockRestore();
      held.destroy();
      nullifier.destroy();
    }
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
  });

  it("rejects a batch for an unheld viewing key before requesting approval or deriving keys", async () => {
    const { address, nullifier, decrypt, keys: held } = keys(bytes(5, 31) as Bytes31);
    try {
      const viewingPublicKey = X25519PublicKey.fromBytes(address.viewingPublicKey.toBytes());
      const other = X25519Keypair.generate().publicKey();
      const output = {
        ciphertext: bytes(7, 50), viewingPublicKey, txViewingPublicKey: other,
        salt: bytes(0, 16) as never, slotIndex: 0, label: "transfer",
      } as const;
      const transaction = { viewingPublicKey, firstNullifier: bytes(1) as Bytes32 };
      await expect(held.decrypt([output, { ...output, viewingPublicKey: other }]))
        .rejects.toMatchObject({ code: "UnknownViewingKey" });
      await expect(held.transactionKeys([transaction, { ...transaction, viewingPublicKey: other }]))
        .rejects.toMatchObject({ code: "UnknownViewingKey" });
      expect(decrypt).not.toHaveBeenCalled();
      await expect(held.decrypt([output])).resolves.toEqual([bytes(7, 50)]);
      const [key] = await held.transactionKeys([transaction]);
      expect(key).toBeDefined();
      key?.destroy();
    } finally {
      held.destroy();
      nullifier.destroy();
    }
  });

  it("validates the whole batch before requesting approval for any item", async () => {
    const { address, nullifier, decrypt, keys: held } = keys(bytes(5, 31) as Bytes31);
    const transfer = {
      ciphertext: bytes(7, 50), viewingPublicKey: address.viewingPublicKey,
      txViewingPublicKey: address.viewingPublicKey, salt: bytes(0, 16) as never,
      slotIndex: 0xffff_ffff, label: "transfer",
    } as const;
    const ringDeposit = { ...transfer, slotIndex: 0, label: "ringDeposit" } as const;
    try {
      for (const invalid of [
        { ...transfer, slotIndex: -1 }, { ...transfer, slotIndex: 1.5 },
        { ...transfer, slotIndex: 0x1_0000_0000 }, { ...transfer, slotIndex: NaN },
        { ...ringDeposit, slotIndex: 1 }, { ...transfer, salt: bytes(0, 15) as never },
        { ...transfer, label: "constructor" as never },
      ]) {
        await expect(held.decrypt([transfer, invalid])).rejects.toMatchObject({ code: "InvalidDecryptItem" });
      }
      expect(decrypt).not.toHaveBeenCalled();
      await expect(held.decrypt([transfer, ringDeposit])).resolves.toEqual([bytes(7, 50), bytes(7, 50)]);
      expect(decrypt.mock.calls[0]?.[0].map(({ slot_index, label }) => [slot_index, label])).toEqual([
        ["4294967295", "Transfer"], ["0", "RingDeposit"],
      ]);
    } finally {
      held.destroy();
      nullifier.destroy();
    }
  });

  it("aborts pending decrypts and prevents new requests after destruction", async () => {
    let finish!: (value: string[]) => void;
    const reply = new Promise<string[]>(resolve => { finish = resolve; });
    const { address, nullifier, decrypt, keys: held } = keys(
      bytes(5, 31) as Bytes31, vi.fn((_items: readonly DecryptItem[], _context?: RequestContext) => reply),
    );
    try {
      const request = {
        ciphertext: bytes(1), viewingPublicKey: address.viewingPublicKey,
        txViewingPublicKey: address.viewingPublicKey, salt: bytes(0, 16) as never,
        slotIndex: 0, label: "transfer",
      } as const;
      const pending = held.decrypt([request]);
      const rejected = expect(pending).rejects.toMatchObject({ code: "KeyHandleDestroyed" });
      const signal = decrypt.mock.calls[0]?.[1]?.signal;
      expect(signal?.aborted).toBe(false);
      held.destroy();
      expect(signal?.aborted).toBe(true);
      await rejected;
      finish(["01"]);
      await expect(held.decrypt([request])).rejects.toMatchObject({ code: "KeyHandleDestroyed" });
      expect(decrypt).toHaveBeenCalledOnce();
    } finally {
      held.destroy();
      nullifier.destroy();
    }
  });

  it("discards plaintext when destruction lands after the callback resolves", async () => {
    let finish!: (value: string[]) => void;
    const reply = new Promise<string[]>(resolve => { finish = resolve; });
    const { address, nullifier, keys: held } = keys(
      bytes(5, 31) as Bytes31, vi.fn((_items: readonly DecryptItem[], _context?: RequestContext) => reply),
    );
    try {
      const pending = held.decrypt([{
        ciphertext: bytes(1), viewingPublicKey: address.viewingPublicKey,
        txViewingPublicKey: address.viewingPublicKey, salt: bytes(0, 16) as never,
        slotIndex: 0, label: "transfer",
      }]);
      const rejection = expect(pending).rejects.toMatchObject({ code: "KeyHandleDestroyed" });
      finish(["01"]);
      // Destroy after awaitWithSignal accepts the reply but before decrypt resumes.
      queueMicrotask(() => queueMicrotask(() => held.destroy()));
      await rejection;
    } finally {
      held.destroy();
      nullifier.destroy();
    }
  });

  it.each(["prove", "proveMerge", "proveIndexed"] as const)(
    "aborts pending %s calls and refuses to start another proof after destruction",
    async (method) => {
      let finish!: () => void;
      const reply = new Promise<void>(resolve => { finish = resolve; });
      const proof = { a: bytes(0, 64), b: bytes(0, 128), c: bytes(0, 64) } as Awaited<ReturnType<LocalKeys["prove"]>>;
      const prove = method === "proveIndexed"
        ? vi.spyOn(LocalKeys.prototype, method).mockImplementation(() => reply.then(() => ({
            proof, resolution: { trees: [], publicInputHash: bytes(0) as Bytes32 },
          })))
        : vi.spyOn(LocalKeys.prototype, method).mockImplementation(() => reply.then(() => proof));
      const controller = new AbortController();
      const { nullifier, keys: held } = keys(bytes(5, 31) as Bytes31);
      try {
        // The stub isolates handle lifetime from the proof input decoder.
        const cancelled = AbortSignal.abort(new DOMException("Request cancelled", "AbortError"));
        await expect(held[method]({} as never, { signal: cancelled })).rejects.toBe(cancelled.reason);
        expect(prove).not.toHaveBeenCalled();
        const pending = held[method]({} as never, { signal: controller.signal, timeoutMs: 50 });
        const signal = prove.mock.calls[0]?.[1]?.signal;
        held.destroy();
        await expect(pending).rejects.toMatchObject({ code: "KeyHandleDestroyed" });
        finish();
        expect(signal?.aborted).toBe(true);
        expect(controller.signal.aborted).toBe(false);
        expect(prove.mock.calls[0]?.[1]?.timeoutMs).toBe(50);
        await expect(held[method]({} as never)).rejects.toMatchObject({ code: "KeyHandleDestroyed" });
        expect(prove).toHaveBeenCalledOnce();
      } finally {
        finish();
        held.destroy();
        nullifier.destroy();
        prove.mockRestore();
      }
    },
  );

  it("clears derived bytes and destroys transaction keys if the handle closes before return", async () => {
    const derived = bytes(5) as Bytes32;
    const minted = ViewingKey.generate();
    const derive = vi.spyOn(LocalKeys.prototype, "derive").mockResolvedValue([derived]);
    const transactionKeys = vi.spyOn(LocalKeys.prototype, "transactionKeys").mockResolvedValue([minted]);
    const { nullifier, keys: held } = keys(bytes(5, 31) as Bytes31);
    try {
      const pendingDerivation = held.derive([]);
      const pendingKeys = held.transactionKeys([]);
      held.destroy();
      await Promise.all([
        expect(pendingDerivation).rejects.toMatchObject({ code: "KeyHandleDestroyed" }),
        expect(pendingKeys).rejects.toMatchObject({ code: "KeyHandleDestroyed" }),
      ]);
      expect(derived).toEqual(bytes(0));
      expect(() => minted.publicKey()).toThrow();
      await expect(held.derive([])).rejects.toMatchObject({ code: "KeyHandleDestroyed" });
      await expect(held.transactionKeys([])).rejects.toMatchObject({ code: "KeyHandleDestroyed" });
      expect(derive).toHaveBeenCalledOnce();
      expect(transactionKeys).toHaveBeenCalledOnce();
    } finally {
      held.destroy();
      nullifier.destroy();
      minted.destroy();
      derive.mockRestore();
      transactionKeys.mockRestore();
    }
  });
});
