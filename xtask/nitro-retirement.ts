import { readFileSync } from "node:fs";
import { requireRetirementPolicy, validateNitroTrust, type NitroTrust } from "../sdk/src/attestation/nitro-policy.js";
import { readPublishedNitroPolicy } from "../sdk/src/attestation/nitro-publication.js";
import { createDecryptionCanary, probeNitroTarget, requireCanaryAgreement } from "../sdk/src/client/nitro-probe.js";
import { remainingReleasePolicyMs } from "../sdk/src/connection/operations.js";
import { MAX_CLOCK_SKEW_MS } from "../sdk/src/protocol/constants.js";
import { parseStrictJson } from "../sdk/src/protocol/json.js";

async function main() {
  const [network, domain, epoch, custodyDigest, mode, value, canaryDigest, ...extra] = process.argv.slice(2);
  const expectedPolicyDigest = mode === "policy" && canaryDigest === undefined ? value : undefined;
  const probe = mode === "probe" && value && canaryDigest ? { seed: value, canaryDigest } : undefined;
  if (!network || !domain || !epoch || !custodyDigest || extra.length || (!expectedPolicyDigest && !probe)) {
    throw new Error("expected network, domain, replacement epoch, custody digest and either probe <seed> <canary-digest> or policy <digest>");
  }
  const trust = parseStrictJson<NitroTrust>(readFileSync(0, "utf8"));
  validateNitroTrust(trust);
  if (trust.network !== network || trust.securityDomainId !== domain ||
      (probe && trust.noteSeedCommitment !== probe.seed)) {
    throw new Error("wallet trust does not match the committed custody domain");
  }
  const signal = AbortSignal.timeout(20_000);
  const startedAt = BigInt(Date.now());
  const before = await readPublishedNitroPolicy(trust, signal);
  requireRetirementPolicy(before, epoch, custodyDigest, expectedPolicyDigest);
  if (!probe) return;
  const candidates = before.policy.targets.filter(target => target.custodyEpoch === epoch && target.custodyDigest === custodyDigest);
  const canary = createDecryptionCanary({ ...trust, canaryDigest: probe.canaryDigest });
  const targets = await Promise.allSettled(candidates.map(async target => {
    const { info, bootstrapSlots, bootedAtMs, window } = await probeNitroTarget(target, trust, { signal, canary });
    return {
      target, window,
      bootstrap: { bootKeyId: info.quorum_key_id, bootedAtMs, slots: [...bootstrapSlots].sort((a, b) => a - b) },
    };
  }));
  signal.throwIfAborted();
  requireCanaryAgreement(targets);
  const after = await readPublishedNitroPolicy(trust, signal);
  requireRetirementPolicy(after, epoch, custodyDigest);
  if (before.text !== after.text) throw new Error("signed wallet policy changed during qualification");
  const now = BigInt(Date.now());
  const matching = targets.flatMap(result => {
    if (result.status === "rejected") return [];
    const { target: { releaseId, pcrs }, bootstrap, window } = result.value;
    const remaining = Math.floor(remainingReleasePolicyMs(window, now));
    if (remaining <= 0) return [];
    const validUntilMs = [after.expiresAt, startedAt + MAX_CLOCK_SKEW_MS, now + BigInt(remaining)]
      .reduce((earliest, limit) => earliest < limit ? earliest : limit);
    return [{ releaseId, pcrs, bootstrap, validUntilMs: validUntilMs.toString() }];
  });
  process.stdout.write(JSON.stringify({ policyDigest: after.checkpoint.digest, targets: matching }));
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
