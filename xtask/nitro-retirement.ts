import { readFileSync } from "node:fs";
import { requireRetirementPolicy, validateNitroTrust, type NitroTrust } from "../sdk/src/attestation/nitro-policy.js";
import { readPublishedNitroPolicy } from "../sdk/src/attestation/nitro-publication.js";
import { probeNitroTarget } from "../sdk/src/client/nitro-probe.js";
import { MAX_CLOCK_SKEW_MS } from "../sdk/src/protocol/constants.js";
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
  const startedAt = BigInt(Date.now());
  const before = await readPublishedNitroPolicy(trust, signal);
  requireRetirementPolicy(before, epoch, custodyDigest);
  const candidates = before.policy.targets.filter(target => target.custodyEpoch === epoch && target.custodyDigest === custodyDigest);
  const targets = await Promise.allSettled(candidates.map(async target => {
    const { info, bootstrapSlots, bootedAtMs, attestedAtMs, certificateValidThroughMs } = await probeNitroTarget(target, trust, signal);
    return {
      target, attestedAtMs, certificateValidThroughMs,
      bootstrap: { bootKeyId: info.quorum_key_id, bootedAtMs, slots: [...bootstrapSlots].sort((a, b) => a - b) },
    };
  }));
  signal.throwIfAborted();
  const after = await readPublishedNitroPolicy(trust, signal);
  requireRetirementPolicy(after, epoch, custodyDigest);
  if (before.text !== after.text) throw new Error("signed wallet policy changed during qualification");
  const matching = targets.flatMap(result => {
    if (result.status === "rejected") return [];
    const { target: { releaseId, pcrs }, bootstrap, attestedAtMs, certificateValidThroughMs } = result.value;
    const validUntilMs = [after.expiresAt, startedAt + MAX_CLOCK_SKEW_MS,
      attestedAtMs + MAX_CLOCK_SKEW_MS + 1n, certificateValidThroughMs + 1n]
      .reduce((first, second) => first < second ? first : second);
    return [{ releaseId, pcrs, bootstrap, validUntilMs: validUntilMs.toString() }];
  });
  process.stdout.write(JSON.stringify({ policyDigest: after.checkpoint.digest, targets: matching }));
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
