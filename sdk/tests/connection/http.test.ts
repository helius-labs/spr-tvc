import { expect, it, vi } from "vitest";
import { fetchWithSignal, readBoundedText } from "../../src/connection/http.js";

it("never buffers a non-streaming response through arrayBuffer", async () => {
  const response = new Response(null);
  const buffer = vi.spyOn(response, "arrayBuffer").mockResolvedValue(new ArrayBuffer(2));
  await expect(readBoundedText(response, 1n)).resolves.toBe("");
  expect(buffer).not.toHaveBeenCalled();
});

it("copies response bytes before a later read reuses the stream's buffer", async () => {
  const byte = new Uint8Array(1);
  let next = 97;
  const response = new Response(new ReadableStream<Uint8Array>({
    pull(controller) {
      if (next === 100) {
        controller.close();
      } else {
        byte[0] = next++;
        controller.enqueue(byte);
      }
    },
  }, { highWaterMark: 0 }));
  await expect(readBoundedText(response, 3n)).resolves.toBe("abc");
});

it("cancels a stream as soon as it exceeds the byte limit", async () => {
  const cancel = vi.fn();
  const chunks = [Uint8Array.of(97, 98), new Uint8Array(), Uint8Array.of(99, 100)];
  const pull = vi.fn((controller: ReadableStreamDefaultController<Uint8Array>) => controller.enqueue(chunks.shift()!));
  const response = new Response(new ReadableStream({ pull, cancel }, { highWaterMark: 0 }));
  await expect(readBoundedText(response, 3n)).rejects.toMatchObject({ code: "ResponseTooLarge" });
  expect(pull).toHaveBeenCalledTimes(3);
  expect(cancel).toHaveBeenCalledOnce();
});

it("stops a stalled response body even if stream cancellation never resolves", async () => {
  const controller = new AbortController();
  const cancel = vi.fn(() => new Promise<void>(() => {}));
  const response = new Response(new ReadableStream({ pull() {}, cancel }));
  const pending = readBoundedText(response, 1024n, controller.signal);
  const rejected = expect(pending).rejects.toThrow("cancelled");
  controller.abort(new Error("cancelled"));
  await rejected;
  expect(cancel).toHaveBeenCalledOnce();
});

it("cancels a response returned by a transport after its caller has left", async () => {
  const controller = new AbortController();
  let finish!: (response: Response) => void;
  const transport = { fetch: vi.fn(() => new Promise<Response>((resolve) => { finish = resolve; })) };
  const pending = fetchWithSignal(transport, new URL("https://tvc.example"), undefined, controller.signal);
  const rejected = expect(pending).rejects.toThrow("cancelled");
  controller.abort(new Error("cancelled"));
  await rejected;
  const cancel = vi.fn();
  finish(new Response(new ReadableStream({ cancel })));
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(cancel).toHaveBeenCalledOnce();
});

it("does not request or read a body for an already cancelled caller", async () => {
  const transport = { fetch: vi.fn() };
  const signal = AbortSignal.abort(new Error("cancelled"));
  await expect(fetchWithSignal(transport, new URL("https://tvc.example"), undefined, signal)).rejects.toThrow("cancelled");
  expect(transport.fetch).not.toHaveBeenCalled();
});
