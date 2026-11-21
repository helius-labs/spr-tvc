import { readFile } from "node:fs/promises";
import { connectNitroTarget, nitroTransport } from "../sdk/src/attestation/nitro-connection.js";
import {
  nitroPublication, validateNitroTrust, verifyRetirementPolicy, type NitroTrust,
} from "../sdk/src/attestation/nitro-policy.js";
import { fetchWithSignal, readBoundedText } from "../sdk/src/connection/http.js";
import { parseStrictJson } from "../sdk/src/protocol/json.js";

async function main() {
  const [path, network, domain, seed, epoch] = process.argv.slice(2);
  if (!path || !epoch) throw new Error("usage: nitro-retirement.ts <wallet-trust> <network> <domain> <seed> <replacement-epoch>");
  const trust = parseStrictJson<NitroTrust>(await readFile(path, "utf8"));
  validateNitroTrust(trust);
  if (trust.network !== network || trust.securityDomainId !== domain || trust.noteSeedCommitment !== seed) {
    throw new Error("wallet trust does not match the committed custody domain");
  }
  const signal = AbortSignal.timeout(12_000);
  const { url } = nitroPublication(trust);
  const response = await fetchWithSignal(nitroTransport, url, {
    headers: { "x-amz-expected-bucket-owner": trust.publication.account },
  }, signal);
  if (!response.ok) throw new Error(`canonical wallet policy returned HTTP ${response.status}`);
  const text = await readBoundedText(response, 32_768n, signal);
  const { policy, checkpoint } = verifyRetirementPolicy(text, trust, epoch, BigInt(Date.now()));
  await Promise.all(policy.targets.map(target => connectNitroTarget(target, trust, signal)));
  verifyRetirementPolicy(text, trust, epoch, BigInt(Date.now()));
  process.stdout.write(checkpoint.digest);
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
