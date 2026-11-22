import { readFileSync } from "node:fs";
import { requireRetirementPolicy, validateNitroTrust, type NitroTrust } from "../sdk/src/attestation/nitro-policy.js";
import { readPublishedNitroPolicy } from "../sdk/src/attestation/nitro-publication.js";
import { probeNitroTarget } from "../sdk/src/client/nitro-probe.js";
import { parseStrictJson } from "../sdk/src/protocol/json.js";

async function main() {
  const [network, domain, seed, epoch, custodyDigest, ...extra] = process.argv.slice(2);
  if (!network || !domain || !seed || !epoch || !custodyDigest || extra.length) {
    throw new Error("usage: nitro-retirement.ts <network> <domain> <seed> <replacement-epoch> <custody-digest> < wallet-trust.json");
  }
  const trust = parseStrictJson<NitroTrust>(readFileSync(0, "utf8"));
  validateNitroTrust(trust);
  if (trust.network !== network || trust.securityDomainId !== domain || trust.noteSeedCommitment !== seed) {
    throw new Error("wallet trust does not match the committed custody domain");
  }
  const signal = AbortSignal.timeout(20_000);
  const before = await readPublishedNitroPolicy(trust, signal);
  requireRetirementPolicy(before, epoch, custodyDigest);
  const candidates = before.policy.targets.filter(target => target.custodyEpoch === epoch && target.custodyDigest === custodyDigest);
  const targets = await Promise.allSettled(candidates.map(async target => {
    const { info, bootstrapSlots, bootedAtMs } = await probeNitroTarget(target, trust, signal);
    return { target, bootstrap: { bootKeyId: info.quorum_key_id, bootedAtMs, slots: [...bootstrapSlots].sort((a, b) => a - b) } };
  }));
  signal.throwIfAborted();
  const after = await readPublishedNitroPolicy(trust, signal);
  requireRetirementPolicy(after, epoch, custodyDigest);
  if (before.text !== after.text) throw new Error("signed wallet policy changed during qualification");
  const matching = targets.flatMap(result => {
    if (result.status === "rejected") return [];
    const { target: { releaseId, pcrs }, bootstrap } = result.value;
    return [{ releaseId, pcrs, bootstrap }];
  });
  process.stdout.write(JSON.stringify({ policyDigest: after.checkpoint.digest, targets: matching }));
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
