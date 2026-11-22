import { createHash, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { verifyNitroCustodyEvidence, verifyNitroRelayRecipient } from "../sdk/src/attestation/boot-proof.js";
import type { NitroPcrs } from "../sdk/src/attestation/nitro-policy.js";
import { requireHex } from "../sdk/src/protocol/hex.js";
import { parseStrictJson } from "../sdk/src/protocol/json.js";

async function main() {
  const [mode, ...extra] = process.argv.slice(2);
  if ((mode !== "recipient" && mode !== "proof") || extra.length) throw new Error("expected recipient or proof mode");
  const { nonce, evidence, pcrs, binding } = parseStrictJson<{
    nonce: string; evidence: string; pcrs: NitroPcrs; binding: string;
  }>(readFileSync(0, "utf8"), mode === "proof" ? ["nonce", "evidence", "pcrs", "binding"] : ["nonce", "evidence", "pcrs"]);
  if (mode === "proof") {
    await verifyNitroCustodyEvidence(requireHex(evidence), requireHex(nonce, 32), requireHex(binding, 32), pcrs, BigInt(Date.now()));
    return;
  }
  const bytes = await verifyNitroRelayRecipient(requireHex(evidence), requireHex(nonce, 32), pcrs);
  const key = createPublicKey({ key: Buffer.from(bytes), format: "der", type: "spki" });
  if (key.asymmetricKeyType !== "rsa" || key.asymmetricKeyDetails?.modulusLength !== 2048 ||
      !key.export({ format: "der", type: "spki" }).equals(bytes)) {
    throw new Error("invalid relay recipient key");
  }
  process.stdout.write(createHash("sha256").update(bytes).digest("hex"));
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
