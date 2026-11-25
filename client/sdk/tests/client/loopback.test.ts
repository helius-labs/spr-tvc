import { generateKeyPairSigner } from "@solana/kit";
import { ViewingKey } from "@heliuslabs/spr";
import { randomSalt } from "@heliuslabs/spr/keypair";
import { expect, it } from "vitest";

import { createLocalDecryptionService } from "../local-service.js";
import { qosDecrypt } from "../../src/crypto/qos.js";
import { decodeLowerHex } from "../../src/wire/hex.js";
import type { DecryptionServiceTransport } from "../../src/connection/http.js";

const endpoint = process.env["DECRYPTION_SERVICE_LOCAL_ENDPOINT"];

it.skipIf(!endpoint)("opens one note for its owner and keeps a replay sealed", async () => {
  const seen: { body: string; text: string }[] = [];
  const transport: DecryptionServiceTransport = {
    async fetch(url, init) {
      const response = await fetch(url, init);
      if (!url.pathname.endsWith("/v1/operations")) return response;
      const text = await response.text();
      seen.push({ body: String(init?.body), text });
      return new Response(text, { status: response.status, headers: response.headers });
    },
  };
  const service = createLocalDecryptionService({
    network: "devnet",
    endpoint: new URL(endpoint!),
    transport,
  });
  const owner = await generateKeyPairSigner();
  const other = await generateKeyPairSigner();
  const keys = await service.keys(owner);
  const sender = ViewingKey.generate();
  try {
    const salt = randomSalt();
    const plaintext = new TextEncoder().encode("ten usdc");
    const request = {
      ciphertext: sender.encryptSlot(keys.address().viewingPublicKey, plaintext, salt, 0),
      viewingPublicKey: keys.address().viewingPublicKey,
      txViewingPublicKey: sender.publicKey(),
      salt,
      slotIndex: 0,
      label: "transfer" as const,
    };
    expect(await keys.decrypt([request])).toEqual([plaintext]);

    const decrypt = seen.at(-1)!;
    const again = await fetch(new URL("/v1/operations", endpoint), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: decrypt.body,
    });
    const againText = await again.text();
    const first = JSON.parse(decrypt.text) as { request_id: string; encrypted_result: string };
    const second = JSON.parse(againText) as { request_id: string; encrypted_result: string };
    expect(second.request_id).toEqual(first.request_id);
    const stranger = crypto.getRandomValues(new Uint8Array(32));
    expect(() => qosDecrypt(stranger, decodeLowerHex(first.encrypted_result))).toThrow();
    expect(() => qosDecrypt(stranger, decodeLowerHex(second.encrypted_result))).toThrow();

    const otherKeys = await service.keys(other);
    try {
      const wrong = await otherKeys.decrypt([request]);
      expect(wrong).not.toEqual([plaintext]);
    } finally {
      otherKeys.destroy();
    }
  } finally {
    keys.destroy();
    sender.destroy();
  }
});
