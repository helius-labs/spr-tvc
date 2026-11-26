import { readFileSync } from "node:fs";
import { generateKeyPairSigner } from "@solana/kit";
import { ViewingKey } from "@heliuslabs/spr";
import { randomSalt } from "@heliuslabs/spr/keypair";
import { expect, it } from "vitest";

import { createDecryptionService } from "../../src/client/decryption.js";
import type { DecryptionServiceTransport } from "../../src/connection/http.js";
import { qosDecrypt } from "../../src/crypto/qos.js";
import { decodeLowerHex } from "../../src/wire/hex.js";
import type { ReleaseTrust } from "../../src/wire/releases.js";

const endpoint = process.env["SPR_E2E_GATEKEEPER_URL"];
const apiKey = process.env["HELIUS_API_KEY"] ?? process.env["API_KEY"];
const pinPath = process.env["SPR_E2E_RELEASE_PIN"];

it.skipIf(!endpoint || !apiKey || !pinPath)(
  "opens one note for its owner",
  async () => {
    const release = JSON.parse(readFileSync(pinPath!, "utf8")) as ReleaseTrust;
    const seen: { body: string; text: string }[] = [];
    const transport: DecryptionServiceTransport = {
      async fetch(url, init) {
        const response = await fetch(url, init);
        if (!url.pathname.endsWith("/v1/decryption/operations")) return response;
        const text = await response.text();
        seen.push({ body: String(init?.body), text });
        return new Response(text, { status: response.status, headers: response.headers });
      },
    };
    const service = createDecryptionService({
      network: "devnet",
      endpoint: new URL(endpoint!),
      apiKey: apiKey!,
      release,
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
      const again = await fetch(new URL("/v1/decryption/operations", endpoint), {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": apiKey! },
        body: decrypt.body,
      });
      const againText = await again.text();
      const first = sealedResult(decrypt.text);
      const second = sealedResult(againText);
      expect(second.requestId).toEqual(first.requestId);
      const stranger = crypto.getRandomValues(new Uint8Array(32));
      expect(() => qosDecrypt(stranger, first.sealed)).toThrow();
      expect(() => qosDecrypt(stranger, second.sealed)).toThrow();

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
  },
);

function sealedResult(text: string): { requestId: string; sealed: Uint8Array } {
  const body = JSON.parse(text) as { response: { request_id: string; encrypted_result: string } };
  return {
    requestId: body.response.request_id,
    sealed: decodeLowerHex(body.response.encrypted_result),
  };
}
