// Covers INV-29 (shared session verification, release expiry renewal, reset & abort isolation).

import { expect, it, vi } from "vitest";
import { MAX_ENCRYPTED_REQUEST_BYTES } from "../../src/wire/constants.js";
import type { ConnectedTvcRuntime } from "../../src/connection/connect.js";
import { sessionFromConnector } from "../../src/connection/session.js";
function runtime(label: string, nowMs: () => bigint = () => 1n): ConnectedTvcRuntime {
  return {
    backend: { endpoint: new URL("https://tvc.example") },
    target: {
      network: "devnet", quorumKeyId: label, quorumKeyEpoch: "1", quorumPublicKey: "",
      maxEncryptedRequestBytes: BigInt(MAX_ENCRYPTED_REQUEST_BYTES),
      maxEncryptedResponseBytes: BigInt(MAX_ENCRYPTED_REQUEST_BYTES),
    },
    transport: { fetch: vi.fn() }, releasePolicyValidFromMs: 0n,
    releasePolicyExpiresAtMs: 999999n, nowMs,
    trustVerifier: { verifyOperationAppProof: vi.fn() },
  };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
const signal = () => new AbortController().signal;

it("verifies once on first use and holds the connection", async () => {
  const connect = vi.fn(async (_signal: AbortSignal) => runtime("held"));
  const session = sessionFromConnector(connect);
  const first = await session.context(signal());
  expect(first).toMatchObject({ target: { quorumKeyId: "held" } });
  await expect(session.context(signal())).resolves.toBe(first);
  expect(connect).toHaveBeenCalledOnce();
});

it("verifies again once the release policy's window no longer holds, and after forget", async () => {
  let now = 1n;
  const connect = vi.fn(async (_signal: AbortSignal) => runtime(`at-${now}`, () => now));
  const session = sessionFromConnector(connect);
  const first = await session.context(signal());
  now = 1_000_000n;
  connect.mockRejectedValueOnce(new Error("ExpiredRequest"));
  await expect(session.context(signal())).rejects.toThrow("ExpiredRequest");
  expect(connect).toHaveBeenCalledTimes(2);
  now = 2n;
  const second = await session.context(signal());
  expect(second).not.toBe(first);
  expect(connect).toHaveBeenCalledTimes(3);

  session.forget(first);
  await expect(session.context(signal())).resolves.toBe(second);
  session.forget(second);
  const third = await session.context(signal());
  expect(third).not.toBe(second);
  expect(connect).toHaveBeenCalledTimes(4);
});

it("verifies anew after reset, and a verification in flight at the reset never becomes current", async () => {
  const ready = deferred<ConnectedTvcRuntime>();
  const connect = vi.fn((_signal: AbortSignal) => ready.promise);
  const session = sessionFromConnector(connect);
  const inFlight = session.context(signal());
  await Promise.resolve();
  session.reset();
  connect.mockResolvedValueOnce(runtime("after"));
  const after = await session.context(signal());
  expect(after.target.quorumKeyId).toBe("after");
  ready.resolve(runtime("before"));
  await expect(inFlight).resolves.toMatchObject({ target: { quorumKeyId: "before" } });
  await expect(session.context(signal())).resolves.toBe(after);

  session.reset();
  connect.mockResolvedValueOnce(runtime("again"));
  await expect(session.context(signal())).resolves.toMatchObject({ target: { quorumKeyId: "again" } });
  expect(connect).toHaveBeenCalledTimes(3);
});

it("lets one caller cancel while another receives the shared verification", async () => {
  const connection = runtime("shared");
  const ready = deferred<ConnectedTvcRuntime>();
  const connect = vi.fn((_signal: AbortSignal) => ready.promise);
  const session = sessionFromConnector(connect);
  const controller = new AbortController();
  const first = session.context(controller.signal);
  const second = session.context(signal());
  const rejected = expect(first).rejects.toThrow("cancelled");
  await Promise.resolve();
  controller.abort(new Error("cancelled"));
  await rejected;
  expect(connect).toHaveBeenCalledOnce();
  expect(connect.mock.calls[0]![0].aborted).toBe(false);
  ready.resolve(connection);
  await expect(second).resolves.toMatchObject({ target: { quorumKeyId: "shared" } });
});

it("aborts an abandoned verification and refuses its late result after a replacement verifies", async () => {
  const ready = deferred<ConnectedTvcRuntime>();
  const connect = vi.fn((_signal: AbortSignal) => ready.promise);
  const session = sessionFromConnector(connect);
  // Start a connector that ignores cancellation, then abandon it.
  const controller = new AbortController();
  const pending = session.context(controller.signal);
  const rejected = expect(pending).rejects.toThrow("cancelled");
  await Promise.resolve();
  controller.abort(new Error("cancelled"));
  await rejected;
  expect(connect.mock.calls[0]![0].aborted).toBe(true);
  connect.mockResolvedValueOnce(runtime("current"));
  const current = await session.context(signal());
  expect(current.target.quorumKeyId).toBe("current");
  ready.resolve(runtime("old"));
  await new Promise((resolve) => setTimeout(resolve, 0));
  await expect(session.context(signal())).resolves.toBe(current);
  expect(connect).toHaveBeenCalledTimes(2);
});

it("does not connect for an aborted caller", async () => {
  const connect = vi.fn(async () => runtime("unused"));
  const session = sessionFromConnector(connect);
  await expect(session.context(AbortSignal.abort(new Error("cancelled")))).rejects.toThrow("cancelled");
  expect(connect).not.toHaveBeenCalled();
});
