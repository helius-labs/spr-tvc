import { address, signatureBytes, type Address, type MessagePartialSigner } from "@solana/kit";
import { p256 } from "@noble/curves/p256";
import { NullifierKey, ViewingKey, initializePoseidon } from "@heliuslabs/spr";
import type { Bytes16, Bytes31 } from "@heliuslabs/spr/keypair";
import { expect, it, vi } from "vitest";

import type { ConnectedTvcRuntime } from "../../src/connection/connect.js";
import { awaitWithSignal } from "../../src/connection/request.js";
import { sessionFromConnector } from "../../src/connection/session.js";
import { qosDecrypt } from "../../src/crypto/qos.js";
import { decodeLowerHex, encodeLowerHex } from "../../src/protocol/hex.js";
import { DecryptionServiceError } from "../../src/protocol/error.js";
import type { ServiceInfo } from "../../src/protocol/types.js";
import * as exchange from "../../src/client/exchange.js";
import { genesisHashForNetwork } from "../../src/protocol/network.js";
import { decryptionServiceFromSession } from "../../src/client/decryption.js";
import { decryptMessage, serviceRequestDigest, type ServiceRequest } from "../../src/protocol/decryption.js";

const ownerAddress = address("11111111111111111111111111111111");

function fixture() {
  const quorum = new Uint8Array(32).fill(1);
  const publicKey = encodeLowerHex(p256.getPublicKey(quorum, false));
  const info = {
    version: 1, network: "devnet", security_domain_id: "00".repeat(32),
    release_id: "release", manifest_digest: "11".repeat(32), executable_digest: "22".repeat(32),
    quorum_public_key: publicKey + publicKey, quorum_key_id: "quorum", quorum_key_epoch: "1",
    supported_operations: ["ServicePublicKeys", "ServiceDecrypt"],
    max_encrypted_request_bytes: "262144", max_encrypted_response_bytes: "262144", proof_type: "",
  } satisfies ServiceInfo;
  const fetch = vi.fn(async (_url: unknown, _init?: RequestInit) => new Response("", { status: 503 }));
  const context: ConnectedTvcRuntime = {
    backend: { endpoint: new URL("https://example.invalid") },
    info, transport: { fetch },
    releasePolicyValidFromMs: 0n, releasePolicyExpiresAtMs: 9999999n, nowMs: () => 1000n,
    trustVerifier: { verifyOperationAppProof: async () => {} },
  };
  return { context, fetch, quorum, info };
}

it("asks for an address's keys from the release it verified", async () => {
  const { context, fetch, quorum, info } = fixture();
  const forget = vi.fn();
  const service = decryptionServiceFromSession({ context: async () => context, forget }, genesisHashForNetwork("devnet"));
  const owner = ownerAddress;

  await expect(service.address(owner)).rejects.toMatchObject({ code: "OperationUnavailable" });

  expect(String(fetch.mock.calls[0]?.[0])).toBe("https://example.invalid/v1/operations");
  const body = JSON.parse(fetch.mock.calls[0]?.[1]?.body as string) as { ciphertext: string };
  expect(Object.keys(body).sort()).toEqual(["ciphertext", "quorum_key_epoch", "quorum_key_id", "version"]);
  const request = JSON.parse(new TextDecoder().decode(qosDecrypt(quorum, decodeLowerHex(body.ciphertext)))) as ServiceRequest;
  expect(request).toMatchObject({
    target_release_id: "release",
    target_manifest_digest: info.manifest_digest,
    target_executable_digest: info.executable_digest,
    operation: { type: "PublicKeys", address: owner },
  });
  // A failed exchange may mean the release moved on.
  expect(forget).toHaveBeenCalledWith(context);
});


it("discards a disconnected native endpoint and reconnects on the next call", async () => {
  const { context, fetch } = fixture();
  fetch.mockRejectedValueOnce(new DecryptionServiceError("EndpointUnavailable"));
  const connect = vi.fn(async () => context);
  const service = decryptionServiceFromSession(sessionFromConnector(connect), genesisHashForNetwork("devnet"));

  await expect(service.address(ownerAddress)).rejects.toMatchObject({ code: "EndpointUnavailable" });
  expect(fetch).toHaveBeenCalledOnce();
  await expect(service.address(ownerAddress)).rejects.toMatchObject({ code: "OperationUnavailable" });
  expect(connect).toHaveBeenCalledTimes(2);
  expect(fetch).toHaveBeenCalledTimes(2);
});

it("checks the serialized request ceiling before asking for a signature or sending bytes", async () => {
  const { context, fetch } = fixture();
  const signMessages = vi.fn();
  await expect(exchange.executeServiceCall({
    ...context, info: { ...context.info, max_encrypted_request_bytes: "512" },
  }, {
    type: "Decrypt",
    owner: { address: ownerAddress, signMessages },
    items: [{
      ciphertext: "aa".repeat(512), ephemeral_viewing_public_key: "04".repeat(33),
      slot_index: "0", salt: "00".repeat(16), label: "Transfer",
    }],
  }, new AbortController().signal)).rejects.toMatchObject({ code: "RequestTooLarge" });
  expect(signMessages).not.toHaveBeenCalled();
  expect(fetch).not.toHaveBeenCalled();
});

it.each([
  { releasePolicyExpiresAtMs: 100_000n, freshness: undefined, expiresAt: "61000" },
  { releasePolicyExpiresAtMs: 30_000n, freshness: undefined, expiresAt: "30001" },
  { releasePolicyExpiresAtMs: 30_000n, freshness: () => 3_000, expiresAt: "4000" },
])("signs the deadline that fits the verified session", async ({ releasePolicyExpiresAtMs, freshness, expiresAt }) => {
  const { context, quorum, fetch } = fixture();
  const signMessages = vi.fn<MessagePartialSigner["signMessages"]>(async () => [
    { [ownerAddress]: signatureBytes(new Uint8Array(64).fill(1)) },
  ]);
  await expect(exchange.executeServiceCall({
    ...context, releasePolicyExpiresAtMs, policyFreshnessRemainingMs: freshness,
  }, {
    type: "Decrypt", owner: { address: ownerAddress, signMessages }, items: [],
  }, new AbortController().signal)).rejects.toMatchObject({ code: "OperationUnavailable" });
  const body = JSON.parse(fetch.mock.calls[0]?.[1]?.body as string) as { ciphertext: string };
  const request = JSON.parse(new TextDecoder().decode(qosDecrypt(quorum, decodeLowerHex(body.ciphertext)))) as ServiceRequest;
  expect(request.operation).toMatchObject({ type: "Decrypt", expires_at_ms: expiresAt });
  expect(signMessages.mock.calls[0]?.[0][0]?.content).toEqual(
    decryptMessage(new Uint8Array(32), "devnet", serviceRequestDigest(request)),
  );
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
    expect(owner.signMessages).toHaveBeenCalledWith(expect.any(Array), { abortSignal: expect.any(AbortSignal) });
    scope.abort(new Error("owner cancelled"));
    await rejected;
    expect(fetch).not.toHaveBeenCalled();
    expect(responseSecret).toEqual(new Uint8Array(32));
  } finally {
    random.mockRestore();
  }
});

it("aborts a stalled owner approval at the end of the release window", async () => {
  vi.useFakeTimers();
  try {
    const { context, fetch } = fixture();
    let approvalSignal: AbortSignal | undefined;
    let returnSignature!: () => void;
    const owner = {
      address: ownerAddress,
      signMessages: vi.fn<MessagePartialSigner["signMessages"]>((_messages, options) => {
        approvalSignal = options?.abortSignal;
        return new Promise(resolve => {
          returnSignature = () => resolve([{ [ownerAddress]: signatureBytes(new Uint8Array(64).fill(1)) }]);
        });
      }),
    };
    const caller = new AbortController();
    const pending = exchange.executeServiceCall({ ...context, releasePolicyExpiresAtMs: 1009n },
      { type: "Decrypt", owner, items: [] }, caller.signal);
    const rejected = expect(pending).rejects.toMatchObject({ code: "ExpiredRequest" });
    expect(approvalSignal?.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(9);
    expect(approvalSignal?.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(approvalSignal?.aborted).toBe(true);
    await rejected;
    returnSignature();
    await Promise.resolve();
    expect(caller.signal.aborted).toBe(false);
    expect(fetch).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  } finally {
    vi.useRealTimers();
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
    const service = decryptionServiceFromSession(sessionFromConnector(connect), genesisHashForNetwork("devnet"), { requestTimeoutMs: timeoutMs });
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
  const proofs = { prove: vi.fn(), proveMerge: vi.fn() };
  const secret = new Uint8Array(31).fill(5) as Bytes31;
  const nullifier = NullifierKey.fromSecret(secret);
  const viewing = ViewingKey.generate();
  const viewingPublicKey = viewing.publicKey();
  const service = decryptionServiceFromSession(
    sessionFromConnector(async () => context), genesisHashForNetwork("devnet"), { requestTimeoutMs: source === "client" ? 10 : undefined },
  );
  const operation = vi.spyOn(exchange, "executeServiceCall")
    .mockResolvedValueOnce({
      type: "PublicKeys",
      viewing_public_key: encodeLowerHex(viewingPublicKey.toBytes()),
      nullifier_public_key: encodeLowerHex(nullifier.publicKey()),
    })
    .mockResolvedValueOnce({ type: "Decrypt", plaintexts: [], nullifier_secret: encodeLowerHex(secret) });
  try {
    const keys = await service.open(owner, proofs);
    try {
      vi.useFakeTimers();
      operation
        .mockImplementationOnce(async () => {
          await new Promise<void>((resolve) => setTimeout(resolve, 6));
          return { type: "Decrypt", plaintexts: Array<string>(256).fill("01"), nullifier_secret: encodeLowerHex(secret) };
        })
        .mockImplementationOnce(async (_context, _operation, signal) =>
          awaitWithSignal(new Promise<never>(() => {}), signal));
      const request = {
        ciphertext: Uint8Array.of(1), viewingPublicKey, txViewingPublicKey: viewingPublicKey,
        salt: new Uint8Array(16) as Bytes16, slotIndex: 0, label: "transfer" as const,
      };
      const pending = keys.decrypt(
        Array.from({ length: 257 }, () => request),
        source === "caller" ? { timeoutMs: 10 } : undefined,
      );
      const rejected = expect(pending).rejects.toMatchObject({ name: "TimeoutError" });
      await vi.advanceTimersByTimeAsync(6);
      const first = operation.mock.calls[2];
      const second = operation.mock.calls[3];
      expect(operation.mock.calls.slice(2).map(([, call]) =>
        call.type === "Decrypt" ? call.items.length : 0)).toEqual([256, 1]);
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

it("binds subsequent replies to the opened owner, nullifier secret and each requested ciphertext length", async () => {
  await initializePoseidon();
  const { context } = fixture();
  const owner = { address: ownerAddress as Address, signMessages: vi.fn() };
  const proofs = { prove: vi.fn(), proveMerge: vi.fn() };
  const secret = new Uint8Array(31).fill(5) as Bytes31;
  const nullifier = NullifierKey.fromSecret(secret);
  const viewing = ViewingKey.generate();
  const viewingPublicKey = viewing.publicKey();
  const service = decryptionServiceFromSession(sessionFromConnector(async () => context), genesisHashForNetwork("devnet"));
  const bootstrap = { type: "Decrypt" as const, plaintexts: [], nullifier_secret: encodeLowerHex(secret) };
  const publicKeys = {
    type: "PublicKeys" as const, viewing_public_key: encodeLowerHex(viewingPublicKey.toBytes()),
    nullifier_public_key: encodeLowerHex(nullifier.publicKey()),
  };
  const operation = vi.spyOn(exchange, "executeServiceCall")
    .mockResolvedValueOnce(publicKeys)
    .mockResolvedValueOnce({ ...bootstrap, nullifier_secret: "06".repeat(31) })
    .mockResolvedValueOnce(publicKeys)
    .mockResolvedValueOnce(bootstrap);
  try {
    await expect(service.open(owner, proofs)).rejects.toMatchObject({ code: "TRANSACTION_KEYS_IDENTITY_MISMATCH" });
    const keys = await service.open(owner, proofs);
    try {
      owner.address = address("So11111111111111111111111111111111111111112");
      const first = {
        ciphertext: Uint8Array.of(1), viewingPublicKey, txViewingPublicKey: viewingPublicKey,
        salt: new Uint8Array(16) as Bytes16, slotIndex: 0, label: "transfer" as const,
      };
      const requests = [first, { ...first, ciphertext: Uint8Array.of(2, 3), slotIndex: 1 }];
      const valid = { ...bootstrap, plaintexts: ["ab", "cdef"] };
      for (const invalid of [
        { ...valid, nullifier_secret: "06".repeat(31) },
        { ...valid, plaintexts: ["ab"] },
        { ...valid, plaintexts: ["cdef", "ab"] },
        { ...valid, plaintexts: ["AB", "cdef"] },
        { ...valid, plaintexts: ["a\n", "cdef"] },
      ]) {
        operation.mockResolvedValueOnce(invalid);
        await expect(keys.decrypt(requests)).rejects.toMatchObject({ code: "ReleaseBindingMismatch" });
      }
      operation.mockResolvedValueOnce(valid);
      await expect(keys.decrypt(requests)).resolves.toEqual([Uint8Array.of(0xab), Uint8Array.of(0xcd, 0xef)]);
      expect(operation.mock.calls.at(-1)?.[1]).toMatchObject({ type: "Decrypt", owner: { address: ownerAddress } });
    } finally {
      keys.destroy();
    }
  } finally {
    operation.mockRestore();
    nullifier.destroy();
    viewing.destroy();
    secret.fill(0);
  }
});
