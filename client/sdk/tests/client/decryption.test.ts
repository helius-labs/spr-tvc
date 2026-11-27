import { address, signatureBytes } from "@solana/kit";
import { p256 } from "@noble/curves/p256";
import { NullifierKey, ViewingKey, initializePoseidon } from "@heliuslabs/spr";
import type { Bytes16, Bytes31 } from "@heliuslabs/spr/keypair";
import { expect, it, vi } from "vitest";

import type { ConnectedTvcRuntime } from "../../src/connection/connect.js";
import { awaitWithSignal } from "../../src/connection/request.js";
import { sessionFromConnector } from "../../src/connection/session.js";
import { qosDecrypt } from "../../src/crypto/qos.js";
import { decodeLowerHex, encodeLowerHex } from "../../src/wire/hex.js";
import { MAX_ENCRYPTED_REQUEST_BYTES } from "../../src/wire/constants.js";
import { DecryptionServiceError, DecryptionServiceHttpError } from "../../src/wire/error.js";
import * as exchange from "../../src/client/exchange.js";
import { decryptionServiceFromSession, signViewGrant } from "../../src/client/decryption.js";
import type { ServiceRequest, ViewGrant } from "../../src/wire/decryption.js";

const ownerAddress = address("11111111111111111111111111111111");
const granteeAddress = address("So11111111111111111111111111111111111111112");

function fixture() {
  const quorum = new Uint8Array(32).fill(1);
  const publicKey = encodeLowerHex(p256.getPublicKey(quorum, false));
  const target = {
    network: "devnet" as const,
    quorumKeyId: "quorum",
    quorumKeyEpoch: "1",
    quorumPublicKey: publicKey + publicKey,
    maxEncryptedRequestBytes: BigInt(MAX_ENCRYPTED_REQUEST_BYTES),
    maxEncryptedResponseBytes: BigInt(MAX_ENCRYPTED_REQUEST_BYTES),
  };
  const fetch = vi.fn(async (_url: unknown, _init?: RequestInit) => new Response("", { status: 503 }));
  const context: ConnectedTvcRuntime = {
    backend: { endpoint: new URL("https://example.invalid") },
    target, transport: { fetch },
    releasePolicyValidFromMs: 0n, releasePolicyExpiresAtMs: 9999999n, nowMs: () => 1000n,
    trustVerifier: { verifyOperationAppProof: async () => {} },
  };
  return { context, fetch, quorum, target };
}

it("asks for an address's keys with the Quorum key from the pin", async () => {
  const { context, fetch, quorum, target } = fixture();
  const forget = vi.fn();
  const service = decryptionServiceFromSession({ context: async () => context, forget, reset: vi.fn() });
  const owner = ownerAddress;

  await expect(service.address(owner)).rejects.toMatchObject({ code: "OperationUnavailable" });

  expect(String(fetch.mock.calls[0]?.[0])).toBe("https://example.invalid/v1/operations");
  const body = JSON.parse(fetch.mock.calls[0]?.[1]?.body as string) as { ciphertext: string };
  expect(Object.keys(body).sort()).toEqual(["ciphertext", "quorum_key_epoch", "quorum_key_id", "version"]);
  const request = JSON.parse(new TextDecoder().decode(qosDecrypt(quorum, decodeLowerHex(body.ciphertext)))) as ServiceRequest;
  expect(request).toMatchObject({
    quorum_key_id: target.quorumKeyId,
    quorum_key_epoch: target.quorumKeyEpoch,
    operation: { type: "PublicKeys", address: owner },
  });
  expect(forget).toHaveBeenCalledWith(context);
});

it("drops the connection when the exchange returns 429", async () => {
  const { context } = fixture();
  const forget = vi.fn();
  const service = decryptionServiceFromSession({ context: async () => context, forget, reset: vi.fn() });
  const operation = vi.spyOn(exchange, "executeServiceCall").mockRejectedValueOnce(
    new DecryptionServiceHttpError("OperationUnavailable", 429, null),
  );
  try {
    await expect(service.address(ownerAddress)).rejects.toMatchObject({ status: 429 });
    expect(forget).toHaveBeenCalledWith(context);
  } finally {
    operation.mockRestore();
  }
});


it("checks the serialized request ceiling before asking for a signature or sending bytes", async () => {
  const { context, fetch } = fixture();
  const signMessages = vi.fn();
  await expect(exchange.executeServiceCall({
    ...context, target: { ...context.target, maxEncryptedRequestBytes: 512n },
  }, {
    type: "Decrypt",
    owner: { address: ownerAddress, signMessages },
    items: [{
      ciphertext: "aa".repeat(512), ephemeral_viewing_public_key: "04".repeat(33),
      slot_index: "0", salt: "00".repeat(16), label: "Transfer", kdf: "HkdfSha256Ctr",
    }],
  }, new AbortController().signal)).rejects.toMatchObject({ code: "RequestTooLarge" });
  expect(signMessages).not.toHaveBeenCalled();
  expect(fetch).not.toHaveBeenCalled();
});


it("stops awaiting a cancelled owner approval and wipes the response key", async () => {
  const { context, fetch } = fixture();
  const scope = new AbortController();
  const responseSecret = new Uint8Array(32).fill(9);
  const random = vi.spyOn(p256.utils, "randomPrivateKey").mockReturnValueOnce(responseSecret);
  const owner = {
    address: ownerAddress,
    signMessages: vi.fn(() => new Promise<never>(() => {})),
  };
  try {
    const pending = exchange.executeServiceCall(context, { type: "Decrypt", owner, items: [] }, scope.signal);
    const rejected = expect(pending).rejects.toThrow("owner cancelled");
    expect(owner.signMessages).toHaveBeenCalledWith(expect.any(Array), { abortSignal: scope.signal });
    scope.abort(new Error("owner cancelled"));
    await rejected;
    expect(fetch).not.toHaveBeenCalled();
    expect(responseSecret).toEqual(new Uint8Array(32));
  } finally {
    random.mockRestore();
  }
});

it("refuses to send a request signed after the release expires", async () => {
  const { context, fetch } = fixture();
  let now = 1000n;
  const owner = {
    address: ownerAddress,
    signMessages: vi.fn(async () => {
      now = context.releasePolicyExpiresAtMs + 1n;
      return [{ [ownerAddress]: signatureBytes(new Uint8Array(64).fill(1)) }];
    }),
  };
  await expect(exchange.executeServiceCall({ ...context, nowMs: () => now }, {
    type: "Decrypt", owner, items: [],
  }, new AbortController().signal)).rejects.toMatchObject({ code: "ExpiredRequest" });
  expect(owner.signMessages).toHaveBeenCalledOnce();
  expect(fetch).not.toHaveBeenCalled();
});

it.each([undefined, 25])("bounds stalled verification with client timeout %s", async (timeoutMs) => {
  vi.useFakeTimers();
  try {
    const connect = vi.fn((_signal: AbortSignal) => new Promise<ConnectedTvcRuntime>(() => {}));
    const service = decryptionServiceFromSession(sessionFromConnector(connect), timeoutMs);
    for (const invalid of [0, -1, NaN, Infinity, 0.5, 2_147_483_648]) {
      await expect(service.address(ownerAddress, { timeoutMs: invalid })).rejects.toThrow("InvalidRequestTimeout");
    }
    expect(connect).not.toHaveBeenCalled();

    const rejected = expect(service.address(ownerAddress)).rejects.toMatchObject({ name: "TimeoutError" });
    const shorter = expect(service.address(ownerAddress, { timeoutMs: 10 })).rejects.toMatchObject({ name: "TimeoutError" });
    await vi.advanceTimersByTimeAsync(10);
    await shorter;
    expect(connect).toHaveBeenCalledOnce();
    expect(connect.mock.calls[0]![0].aborted).toBe(false);
    await vi.advanceTimersByTimeAsync((timeoutMs ?? 120_000) - 10);
    await rejected;
    expect(connect.mock.calls[0]![0].aborted).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  } finally {
    vi.useRealTimers();
  }
});

it.each(["caller", "client"])("uses one %s deadline across all decrypt batches", async (source) => {
  await initializePoseidon();
  const { context } = fixture();
  const owner = { address: ownerAddress, signMessages: vi.fn() };
  const secret = new Uint8Array(31).fill(5) as Bytes31;
  const nullifier = NullifierKey.fromSecret(secret);
  const viewing = ViewingKey.generate();
  const viewingPublicKey = viewing.publicKey();
  const service = decryptionServiceFromSession(
    sessionFromConnector(async () => context), source === "client" ? 10 : undefined,
  );
  const operation = vi.spyOn(exchange, "executeServiceCall")
    .mockResolvedValueOnce({
      type: "PublicKeys",
      viewing_public_key: encodeLowerHex(viewingPublicKey.toBytes()),
      nullifier_public_key: encodeLowerHex(nullifier.publicKey()),
    });
  try {
    const keys = await service.keys(owner);
    try {
      vi.useFakeTimers();
      operation
        .mockImplementationOnce(async () => {
          throw new DecryptionServiceError("RequestTooLarge");
        })
        .mockImplementationOnce(async () => {
          await new Promise<void>((resolve) => setTimeout(resolve, 6));
          return { type: "Decrypt", plaintexts: Array<string>(500).fill("01"), nullifier_secret: encodeLowerHex(secret) };
        })
        .mockImplementationOnce(async (_context, _operation, signal) =>
          awaitWithSignal(new Promise<never>(() => {}), signal));
      const request = {
        ciphertext: Uint8Array.of(1), viewingPublicKey, txViewingPublicKey: viewingPublicKey,
        salt: new Uint8Array(16) as Bytes16, slotIndex: 0, label: "transfer" as const,
      };
      const pending = keys.decrypt(
        Array.from({ length: 1000 }, () => request),
        source === "caller" ? { timeoutMs: 10 } : undefined,
      );
      const rejected = expect(pending).rejects.toMatchObject({ name: "TimeoutError" });
      await vi.advanceTimersByTimeAsync(6);
      const calls = operation.mock.calls.slice(1);
      const first = calls[1];
      const second = calls[2];
      expect(calls.map(([, call]) =>
        call.type === "Decrypt" ? call.items.length : 0)).toEqual([1000, 500, 500]);
      expect(second?.[2]).toBe(first?.[2]);
      expect(first?.[2].aborted).toBe(false);
      await vi.advanceTimersByTimeAsync(4);
      await rejected;
      expect(first?.[2].aborted).toBe(true);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      keys.destroy();
    }
  } finally {
    operation.mockRestore();
    nullifier.destroy();
    viewing.destroy();
    vi.useRealTimers();
  }
});

it("rejects self-grants and invalid networks before signing a view grant", async () => {
  const signMessages = vi.fn();
  const owner = { address: ownerAddress, signMessages };
  await expect(
    signViewGrant(owner, {
      grantee: ownerAddress,
      network: "devnet",
      quorumKeyId: "quorum",
      quorumKeyEpoch: 1n,
      notBeforeMs: 1000n,
      expiryMs: 2000n,
    }),
  ).rejects.toMatchObject({ code: "InvalidSignature" });
  await expect(
    signViewGrant(owner, {
      grantee: granteeAddress,
      network: "testnet" as unknown as "devnet",
      quorumKeyId: "quorum",
      quorumKeyEpoch: 1n,
      notBeforeMs: 1000n,
      expiryMs: 2000n,
    }),
  ).rejects.toMatchObject({ code: "UnknownNetwork" });
  expect(signMessages).not.toHaveBeenCalled();
});

it("validates grant target fields before fetching keys or prompting for a decrypt signature", async () => {
  const { context, fetch } = fixture();
  const signMessages = vi.fn();
  const grantee = { address: granteeAddress, signMessages };
  const service = decryptionServiceFromSession(sessionFromConnector(async () => context));
  const baseGrant: ViewGrant = {
    owner: ownerAddress,
    grantee: granteeAddress,
    network: "devnet",
    quorum_key_id: "quorum",
    quorum_key_epoch: "1",
    not_before_ms: "500",
    expiry_ms: "5000",
    signature: "00".repeat(64),
  };

  for (const [patch, code] of [
    [{ owner: granteeAddress }, "InvalidSignature"],
    [{ grantee: ownerAddress }, "InvalidSignature"],
    [{ network: "mainnet" as const }, "NetworkMismatch"],
    [{ quorum_key_id: "other" }, "ReleaseBindingMismatch"],
    [{ quorum_key_epoch: "2" }, "QuorumKeyEpochMismatch"],
    [{ expiry_ms: "999" }, "ExpiredRequest"],
  ] as const) {
    const grant = { ...baseGrant, ...patch };
    await expect(service.keys(grantee, { grant })).rejects.toMatchObject({ code });
    await expect(
      exchange.executeServiceCall(
        context,
        { type: "Decrypt", owner: grantee, items: [], grant },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ code });
  }
  expect(signMessages).not.toHaveBeenCalled();
  expect(fetch).not.toHaveBeenCalled();
});
