import { constants } from "node:fs";
import { open } from "node:fs/promises";

export async function readBoundedDocument(path: string, maxBytes: number): Promise<string> {
  const file = await open(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    if (!(await file.stat()).isFile()) throw new Error("expected a regular JSON document");
    const buffer = Buffer.alloc(maxBytes + 1);
    let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await file.read(buffer, size, buffer.length - size, size);
      if (bytesRead === 0) break;
      size += bytesRead;
    }
    if (size > maxBytes) throw new Error(`JSON document exceeds ${maxBytes / 1024} KiB`);
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buffer.subarray(0, size));
  } finally {
    await file.close();
  }
}
