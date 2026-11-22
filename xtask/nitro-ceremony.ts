import { readFile, writeFile } from "node:fs/promises";
import { verifyCustodyReceipt, type CustodyReceipt } from "../sdk/src/attestation/nitro-custody.js";
import { readBoundedText } from "../sdk/src/connection/http.js";
import { decodeDecimalU64, encodeDecimalU64 } from "../sdk/src/protocol/decimal.js";
import { encodeLowerHex, requireHex } from "../sdk/src/protocol/hex.js";
import { parseStrictJson } from "../sdk/src/protocol/json.js";
import type { Network } from "../sdk/src/protocol/types.js";
import type { NitroPcrs, NitroTargetPcrs } from "../sdk/src/attestation/nitro-policy.js";

type Configuration = {
  releaseId: string;
  securityDomainId: string;
  deployment: {
    mode: string;
    recipientPublicKeys: string[];
    previous?: { noteSeedCommitment: string; epoch: string };
  };
};

type Capture = {
  receipt: CustodyReceipt;
  evidence: string;
  nonce: string;
  verifiedAtMs: string;
  configuration: Configuration;
  pcrs: NitroPcrs | NitroTargetPcrs;
};

function expectation(configuration: Configuration, network: Network, pcrs: NitroPcrs | NitroTargetPcrs) {
  const { releaseId, securityDomainId, deployment } = configuration;
  const { mode, previous, recipientPublicKeys } = deployment;
  if (!((mode === "rotate" && previous) || (mode === "initialize" && !previous))) {
    throw new Error("configuration does not start a custody ceremony");
  }
  return {
    network, releaseId, securityDomainId, pcrs, recipientPublicKeys,
    epoch: previous ? encodeDecimalU64(decodeDecimalU64(previous.epoch) + 1n) : "1",
    ...(previous ? { noteSeedCommitment: previous.noteSeedCommitment } : {}),
  };
}

async function verifyCapture(): Promise<void> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 65_536) throw new Error("custody capture exceeds 64 KiB");
    chunks.push(chunk);
  }
  const { receipt, evidence, nonce, configuration, pcrs, verifiedAtMs } = parseStrictJson<Capture>(
    Buffer.concat(chunks).toString("utf8"), ["receipt", "evidence", "nonce", "configuration", "pcrs", "verifiedAtMs"],
  );
  await verifyCustodyReceipt(JSON.stringify({ result: receipt, evidence }), expectation(configuration, receipt.network, pcrs),
    requireHex(nonce, 32), decodeDecimalU64(verifiedAtMs));
}

async function main(): Promise<void> {
  if (process.argv[2] === "verify") return verifyCapture();
  const [endpoint, configuration, pinFile, network, output] = process.argv.slice(2);
  if (!endpoint || !configuration || !pinFile || (network !== "devnet" && network !== "mainnet") || !output) {
    throw new Error("usage: nitro-ceremony.ts <loopback-url> <configuration.json> <pcrs.json> <devnet|mainnet> <receipt.json>");
  }
  const url = new URL("/custody", endpoint);
  if (url.protocol !== "http:" || !["127.0.0.1", "[::1]"].includes(url.hostname) || url.username || url.password) {
    throw new Error("use an SSM loopback forwarding endpoint");
  }
  const config = parseStrictJson<Configuration>(await readFile(configuration, "utf8"),
    ["releaseId", "securityDomainId", "deployment"]);
  const pcrs = JSON.parse(await readFile(pinFile, "utf8")) as NitroPcrs | NitroTargetPcrs;
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const signal = AbortSignal.timeout(10_000);
  const response = await fetch(url, { method: "POST", body: nonce, redirect: "error", signal });
  if (!response.ok) throw new Error(`custody ceremony returned HTTP ${response.status}`);
  const body = await readBoundedText(response, 49_152n, signal);
  const now = BigInt(Date.now());
  const receipt = await verifyCustodyReceipt(body, expectation(config, network, pcrs), nonce, now);
  const { evidence } = parseStrictJson<{ evidence: string }>(body, ["result", "evidence"]);
  const capture: Capture = {
    receipt, evidence, nonce: encodeLowerHex(nonce), configuration: config, pcrs, verifiedAtMs: encodeDecimalU64(now),
  };
  await writeFile(output, JSON.stringify(capture, null, 2) + "\n", { flag: "wx", mode: 0o600 });
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
