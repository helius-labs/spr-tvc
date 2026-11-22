import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { createServer } from "node:http";
import { once } from "node:events";
import { p256 } from "../../sdk/node_modules/@noble/curves/p256.js";
import { setTimeout } from "node:timers/promises";
import { sha256 } from "../../sdk/node_modules/@noble/hashes/sha256.js";
import { address, generateKeyPairSigner, type Signature } from "../../sdk/node_modules/@solana/kit/dist/index.node.mjs";
import { SOL_MINT, ViewingKey, Wallet, initializePoseidon } from "../../sdk/node_modules/@heliuslabs/spr/dist/index.js";
import { DEFAULT_TREE_ID } from "../../sdk/node_modules/@heliuslabs/spr/dist/interface/index.js";
import { randomSalt } from "../../sdk/node_modules/@heliuslabs/spr/dist/keypair/index.js";
import {
  AssetRegistry,
  createProofOutput,
  decryptTransactions,
  encodeConfidentialSlots,
} from "../../sdk/node_modules/@heliuslabs/spr/dist/transaction/index.js";
import { verifyNativeNitroEvidence } from "../../sdk/src/attestation/boot-proof.js";
import {
  advancesNitroPolicy, createNitroDecryptionService, type NitroPolicy,
  type NitroPolicyCheckpoint, type NitroTarget, type NitroTrust,
} from "../../sdk/src/client/nitro.js";
import { nitroCustodySigningDigest, nitroPolicySigningDigest, nitroPublication } from "../../sdk/src/attestation/nitro-policy.js";
import { signP256Prehash } from "../../sdk/src/crypto/p256.js";
import { encodeLowerHex, requireHex } from "../../sdk/src/protocol/hex.js";
import type { ServiceInfo } from "../../sdk/src/protocol/types.js";
import { canonicalizeJsonValue } from "../../sdk/src/protocol/jcs.js";

const [url, directory, replacementUrl] = process.argv.slice(2);
assert.ok(url && directory, "usage: rehearsal.mts <endpoint> <test directory> [replacement endpoint]");
const endpoint = new URL(url);
const owner = await generateKeyPairSigner();
const proofs = {
  prove() { throw new Error("test only opens the note"); },
  proveMerge() { throw new Error("test only opens the note"); },
};

function target(name: string): NitroTarget {
  const pin = JSON.parse(readFileSync(resolve(directory, name + "-pin.json"), "utf8"));
  return { ...pin, endpoint: name === "b" && replacementUrl ? new URL(replacementUrl).href : endpoint.href };
}
const { domain, seed } = JSON.parse(readFileSync(resolve(directory, "inputs.json"), "utf8"));
const secrets = Array.from({ length: 3 }, () => p256.utils.randomPrivateKey());
const custodySecrets = Array.from({ length: 3 }, () => p256.utils.randomPrivateKey());
const trust = {
  network: "devnet", securityDomainId: domain, noteSeedCommitment: seed,
  minimumSequence: "1", minimumCustodyEpoch: "1", threshold: 2,
  publications: [
    { bucket: "rehearsal-policy", region: "eu-north-1", account: "000000000000" },
    { bucket: "rehearsal-peer", region: "eu-west-1", account: "000000000001" },
  ],
  keys: secrets.map(secret => encodeLowerHex(p256.getPublicKey(secret, false))),
  custodyKeys: custodySecrets.map(secret => encodeLowerHex(p256.getPublicKey(secret, false))),
} satisfies Omit<NitroTrust, "minimumPolicyDigest">;
const start = Date.now() - 30_000;
const heads: [string, string] = ["", ""];
function signPolicy(sequence: string, replicas: readonly NitroTarget[], minimumCustodyEpoch: string, previous?: string): string {
  const policy: NitroPolicy = {
    version: 1, action: "activate", recoveryOnly: false, network: trust.network, securityDomainId: domain, noteSeedCommitment: seed,
    publications: trust.publications,
    validFromMs: String(start), expiresAtMs: String(start + 15 * 60_000),
    sequence, targets: replicas, minimumCustodyEpoch,
    previousPolicyDigest: previous === undefined ? null : encodeLowerHex(nitroPolicySigningDigest(JSON.parse(previous).policy)),
  };
  const digest = nitroPolicySigningDigest(policy);
  const signatures = secrets.slice(0, 2).map((secret, i) => ({
    key: trust.keys[i]!, signature: encodeLowerHex(signP256Prehash(secret, digest)),
  }));
  const custodySignatures = custodySecrets.slice(0, 2).map((secret, i) => ({
    key: trust.custodyKeys[i]!, signature: encodeLowerHex(signP256Prehash(secret, nitroCustodySigningDigest(policy))),
  }));
  return JSON.stringify({ policy, signatures, custodySignatures });
}
const server = createServer((request, response) => {
  const index = paths.indexOf(request.url ?? "");
  const publication = trust.publications[index];
  if (!publication || publication.account !== request.headers["x-amz-expected-bucket-owner"]) {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, { "Content-Type": "application/json" }).end(heads[index]);
});
const paths = ["/primary", "/mirror"];
server.listen(0, "127.0.0.1");
await once(server, "listening");
server.unref();
const listener = server.address();
assert.ok(listener && typeof listener === "object");
const origin = `http://127.0.0.1:${listener.port}`;
const policyUrls = trust.publications.map(publication => nitroPublication(trust, publication).url.href);
const networkFetch = globalThis.fetch;
// Only the two policy reads use local stand-ins. Enclave traffic uses the live endpoints.
globalThis.fetch = (input, init) => {
  const index = input instanceof URL ? policyUrls.indexOf(input.href) : -1;
  return networkFetch(index === -1 ? input : new URL(paths[index]!, origin), init);
};
const checkpoint: { value?: NitroPolicyCheckpoint } = {};
function clientFor(state = checkpoint) {
  return createNitroDecryptionService({
    trust: { ...trust, minimumPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(JSON.parse(initial).policy)) },
    policyStore: { async current() { return state.value; }, async accept(update) {
      if (!advancesNitroPolicy(state.value, update)) return false;
      state.value = update[0].checkpoint;
      return true;
    } },
  });
}

function discoveryBinding(boot: object): Uint8Array {
  return sha256(new TextEncoder().encode("SPR/native-nitro/discovery/v1" + canonicalizeJsonValue(boot)));
}

async function checkEvidence(pin: NitroTarget) {
  const signal = AbortSignal.timeout(10_000);
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const response = await fetch(new URL("v1/nitro/attestation", pin.endpoint), {
    method: "POST",
    body: nonce,
    signal,
  });
  assert.equal(response.status, 200);
  const decoded = await response.json() as { boot: { info: ServiceInfo; bootstrapSlots: number[]; bootedAtMs: string }; evidence: string };
  const { boot } = decoded;
  const { info, bootstrapSlots } = boot;
  const evidence = requireHex(decoded.evidence);
  const now = BigInt(Date.now());
  const binding = discoveryBinding(boot);
  const { proofKey } = await verifyNativeNitroEvidence(evidence, nonce, binding, pin.pcrs, now);
  await assert.rejects(
    verifyNativeNitroEvidence(evidence, crypto.getRandomValues(new Uint8Array(32)), binding, pin.pcrs, now),
    /BootProofUnverified/,
  );
  const fakeTransport = "00".repeat(info.quorum_public_key.length / 2);
  await assert.rejects(
    verifyNativeNitroEvidence(evidence, nonce, discoveryBinding({ ...boot, info: { ...info, quorum_public_key: fakeTransport } }), pin.pcrs, now),
    /BootProofUnverified/,
  );
  await assert.rejects(
    verifyNativeNitroEvidence(evidence, nonce, discoveryBinding({
      ...boot, bootstrapSlots: [bootstrapSlots[1], bootstrapSlots[0], bootstrapSlots[2]],
    }), pin.pcrs, now), /BootProofUnverified/,
  );
  writeFileSync(resolve(directory, pin.releaseId + "-evidence.json"),
    JSON.stringify({ now: String(now), nonce: encodeLowerHex(nonce), binding: encodeLowerHex(binding),
      pcrs: pin.pcrs, proofKey, boot, evidence: decoded.evidence }, null, 2));
  return { info, proofKey };
}

await initializePoseidon();
const originalPin = target("a");
const initial = signPolicy("1", [originalPin], "1");
heads.fill(initial);
const original = await checkEvidence(originalPin);
const client = clientFor();
const recipient = await client.address(owner.address);
const amount = 13n;
const output = createProofOutput({ ownerAddress: recipient, asset: SOL_MINT, amount });
const sender = ViewingKey.generate();
const salt = randomSalt();
const [slot] = encodeConfidentialSlots([output], new AssetRegistry(), sender, salt);
assert.ok(slot);
const tx = {
  slot: 1n,
  txSignature: "1".repeat(64) as Signature,
  txViewingPublicKey: sender.publicKey(),
  salt,
  outputSlots: [{
    viewTag: slot.viewTag,
    payload: slot.data,
    outputContext: {
      hash: output.hash(DEFAULT_TREE_ID),
      tree: address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3"),
      leafIndex: 0n,
    },
  }],
  messages: [],
  nullifiers: [],
  proofless: false,
};
sender.destroy();

async function openNote(service: typeof client, signer = owner) {
  const keys = await service.open(signer, proofs);
  try {
    const wallet = new Wallet({ identity: keys.address() });
    await decryptTransactions({ wallet, keys, transactions: [tx] });
    return wallet.utxos().map(({ utxo }) => utxo.amount);
  } finally {
    keys.destroy();
  }
}

assert.deepEqual(await openNote(client), [amount]);
assert.deepEqual(await openNote(client, await generateKeyPairSigner()), []);
console.log("Image A opened the note. The verifier rejected a replayed nonce and a substituted transport key.");
writeFileSync(resolve(directory, "note-created"), "");
async function waitForMarker(name: string) {
  const marker = resolve(directory, name);
  for (let attempt = 0; attempt < 300 && !existsSync(marker); attempt++) await setTimeout(1000);
  assert.ok(existsSync(marker), `timed out waiting for ${name}`);
}
await waitForMarker("move-ready");

const recoveredPin = target("b");
heads[0] = signPolicy("1", [{ ...recoveredPin, pcrs: originalPin.pcrs }], "1");
await assert.rejects(clientFor().address(owner.address), /ReleasePolicyInvalid/);
heads[0] = signPolicy("2", [{ ...recoveredPin, pcrs: originalPin.pcrs }], "1", initial);
// This policy advances the checkpoint even though attestation fails.
await assert.rejects(clientFor({}).address(owner.address), /BootProofUnverified/);
const recovered = await checkEvidence(recoveredPin);
assert.notEqual(recovered.info.quorum_public_key, original.info.quorum_public_key);
assert.notEqual(recovered.proofKey, original.proofKey);
const unavailable = { ...recoveredPin, endpoint: new URL("offline/", recoveredPin.endpoint).href };
const overlap = signPolicy("2", replacementUrl ? [unavailable, recoveredPin, originalPin] : [unavailable, recoveredPin], "1", initial);
heads[0] = overlap;
const restored = clientFor();
const restoredRecipient = await restored.address(owner.address);
assert.deepEqual(restoredRecipient.viewingPublicKey.toBytes(), recipient.viewingPublicKey.toBytes());
assert.deepEqual(restoredRecipient.nullifierPublicKey, recipient.nullifierPublicKey);
assert.deepEqual(await openNote(restored), [amount]);
heads[1] = overlap;
console.log("Image B rejected the old PCR pin and opened the same note. Both connection keys rotated and both note keys stayed stable.");
if (replacementUrl) {
  writeFileSync(resolve(directory, "before-retire"), "");
  await waitForMarker("old-retired");
  const old = await fetch(new URL("health", originalPin.endpoint), { signal: AbortSignal.timeout(3000) }).catch(() => undefined);
  assert.ok(!old?.ok, "image A was still serving after retirement");
}
const promoted = signPolicy("3", [recoveredPin], recoveredPin.custodyEpoch, overlap);
heads[0] = promoted;
assert.deepEqual(await openNote(clientFor()), [amount]);
heads[1] = promoted;
console.log("The owner reopened the note under the replacement custody epoch.");
heads[1] = overlap;
const fresh: { value?: NitroPolicyCheckpoint } = {};
assert.deepEqual(await openNote(clientFor(fresh)), [amount]);
assert.equal(fresh.value?.sequence, "3");
console.log("A fresh wallet used the primary's revision while the mirror served its predecessor.");
heads[0] = overlap;
heads[1] = promoted;
const restoredCheckpoint: { value?: NitroPolicyCheckpoint } = {};
await assert.rejects(clientFor(restoredCheckpoint).address(owner.address), /ReleasePolicyInvalid/);
assert.equal(restoredCheckpoint.value, undefined);
heads.fill(promoted);
console.log("A wallet with no checkpoint refused a primary older than the mirror.");
if (BigInt(recoveredPin.custodyEpoch) > BigInt(originalPin.custodyEpoch)) {
  heads[0] = signPolicy("4", [originalPin], originalPin.custodyEpoch, promoted);
  await assert.rejects(clientFor().address(owner.address), /ReleasePolicyInvalid/);
  console.log("A higher-sequence policy could not restore the retired custody epoch.");
}
heads.fill(initial);
await assert.rejects(clientFor().address(owner.address), /policy rollback/);
console.log("A new SDK client rejected an older signed policy using the stored checkpoint.");
secrets.forEach(secret => secret.fill(0));
server.close();
