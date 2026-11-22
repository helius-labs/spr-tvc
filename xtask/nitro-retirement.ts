import { readFile } from "node:fs/promises";
import { connectNitroTarget } from "../sdk/src/attestation/nitro-connection.js";
import { requireRetirementPolicy, validateNitroTrust, type NitroTrust } from "../sdk/src/attestation/nitro-policy.js";
import { readPublishedNitroPolicy } from "../sdk/src/attestation/nitro-publication.js";
import { parseStrictJson } from "../sdk/src/protocol/json.js";

async function main() {
  const [path, network, domain, seed, epoch, custodyDigest] = process.argv.slice(2);
  if (!path || !epoch || !custodyDigest) {
    throw new Error("usage: nitro-retirement.ts <wallet-trust> <network> <domain> <seed> <replacement-epoch> <custody-digest>");
  }
  const trust = parseStrictJson<NitroTrust>(await readFile(path, "utf8"));
  validateNitroTrust(trust);
  if (trust.network !== network || trust.securityDomainId !== domain || trust.noteSeedCommitment !== seed) {
    throw new Error("wallet trust does not match the committed custody domain");
  }
  const signal = AbortSignal.timeout(15_000);
  const before = await readPublishedNitroPolicy(trust, signal);
  requireRetirementPolicy(before, epoch, custodyDigest);
  await Promise.all(before.policy.targets.map(target => connectNitroTarget(target, trust, signal)));
  const after = await readPublishedNitroPolicy(trust, signal);
  requireRetirementPolicy(after, epoch, custodyDigest);
  if (before.checkpoint.digest !== after.checkpoint.digest) throw new Error("wallet policy changed during qualification");
  process.stdout.write(after.checkpoint.digest);
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
