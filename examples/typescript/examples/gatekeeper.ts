import { readFileSync } from "node:fs";

import {
  createDecryptionService,
  type DecryptionServiceConfig,
} from "@heliuslabs/spr-decryption-service";

import { noteFor, owner, sameBytes } from "../src/lib.js";

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") {
    console.error(`Set ${name}`);
    process.exit(1);
  }
  return value;
}

const apiKey = process.env["HELIUS_API_KEY"] ?? process.env["API_KEY"];
if (apiKey === undefined || apiKey === "") {
  console.error("Set HELIUS_API_KEY or API_KEY");
  process.exit(1);
}

const service = createDecryptionService({
  network: "devnet",
  endpoint: new URL(required("SPR_E2E_GATEKEEPER_URL")),
  apiKey,
  release: JSON.parse(readFileSync(required("SPR_E2E_RELEASE_PIN"), "utf8")) as NonNullable<
    DecryptionServiceConfig["release"]
  >,
});
const keys = await service.keys(await owner());
try {
  const plaintext = new TextEncoder().encode("ten usdc");
  const opened = await keys.decrypt([noteFor(keys.address().viewingPublicKey, plaintext, 0)]);
  const note = opened[0];
  if (note === undefined || !sameBytes(note, plaintext)) process.exit(1);
  console.log(`ok plaintext=${new TextDecoder().decode(note)}`);
} finally {
  keys.destroy();
}
