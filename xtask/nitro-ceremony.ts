import { readFile, writeFile } from "node:fs/promises";
import { verifyCustodyReceipt } from "../sdk/src/attestation/nitro-custody.js";
import { readBoundedText } from "../sdk/src/connection/http.js";
import { decodeDecimalU64, encodeDecimalU64 } from "../sdk/src/protocol/decimal.js";
import type { NitroPcrs } from "../sdk/src/attestation/nitro-policy.js";

async function main(): Promise<void> {
  const [endpoint, configuration, pinFile, network, output] = process.argv.slice(2);
  if (!endpoint || !configuration || !pinFile || (network !== "devnet" && network !== "mainnet") || !output) {
    throw new Error("usage: nitro-ceremony.ts <loopback-url> <configuration.json> <pcrs.json> <devnet|mainnet> <receipt.json>");
  }
  const url = new URL("/custody", endpoint);
  if (url.protocol !== "http:" || !["127.0.0.1", "[::1]"].includes(url.hostname) || url.username || url.password) {
    throw new Error("use an SSM loopback forwarding endpoint");
  }
  const { releaseId, securityDomainId, deployment } = JSON.parse(await readFile(configuration, "utf8")) as {
    releaseId: string;
    securityDomainId: string;
    deployment: {
      mode: string;
      recipientPublicKeys: string[];
      previous?: { noteSeedCommitment: string; epoch: string };
    };
  };
  const { mode, previous, recipientPublicKeys } = deployment;
  if (!((mode === "rotate" && previous) || (mode === "initialize" && !previous))) {
    throw new Error("configuration does not start a custody ceremony");
  }
  const pcrs = JSON.parse(await readFile(pinFile, "utf8")) as NitroPcrs;
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const signal = AbortSignal.timeout(10_000);
  const response = await fetch(url, { method: "POST", body: nonce, redirect: "error", signal });
  if (!response.ok) throw new Error(`custody ceremony returned HTTP ${response.status}`);
  const receipt = await verifyCustodyReceipt(await readBoundedText(response, 49_152n, signal), {
    network, releaseId, securityDomainId, pcrs, recipientPublicKeys,
    epoch: previous ? encodeDecimalU64(decodeDecimalU64(previous.epoch) + 1n) : "1",
    ...(previous ? { noteSeedCommitment: previous.noteSeedCommitment } : {}),
  }, nonce, BigInt(Date.now()));
  await writeFile(output, JSON.stringify(receipt, null, 2) + "\n", { flag: "wx", mode: 0o600 });
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
