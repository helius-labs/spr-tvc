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
import { nitroPolicySigningDigest } from "../../sdk/src/attestation/nitro-policy.js";
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
const trust: NitroTrust = {
  network: "devnet", securityDomainId: domain, noteSeedCommitment: seed,
  minimumSequence: "1", minimumCustodyEpoch: "1", threshold: 2,
  keys: secrets.map(secret => encodeLowerHex(p256.getPublicKey(secret, false))),
};
const start = Date.now() - 30_000;
let signedPolicy: string;
function signPolicy(sequence: string, replicas: readonly NitroTarget[], minimumCustodyEpoch = "1"): string {
  const policy: NitroPolicy = {
    version: 1, action: "activate", network: trust.network, securityDomainId: domain, noteSeedCommitment: seed,
    validFromMs: String(start), expiresAtMs: String(start + 15 * 60_000),
    sequence, targets: replicas, minimumCustodyEpoch,
  };
  const digest = nitroPolicySigningDigest(policy);
  const signatures = secrets.slice(0, 2).map((secret, i) => ({
    key: trust.keys[i]!, signature: encodeLowerHex(signP256Prehash(secret, digest)),
  }));
  return JSON.stringify({ policy, signatures });
}
const server = createServer((request, response) => {
  if (request.url !== "/policy") {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, { "Content-Type": "application/json" }).end(signedPolicy);
});
server.listen(0, "127.0.0.1");
await once(server, "listening");
server.unref();
const listener = server.address();
assert.ok(listener && typeof listener === "object");
const policyUrl = new URL(`http://127.0.0.1:${listener.port}/policy`);
let checkpoint: NitroPolicyCheckpoint | undefined;
function clientFor() {
  return createNitroDecryptionService({
    trust, policyUrl,
    policyStore: { async current() { return checkpoint; }, async accept(next) {
      if (!advancesNitroPolicy(checkpoint, next)) return false;
      checkpoint = next;
      return true;
    } },
  });
}

function discoveryBinding(info: object): Uint8Array {
  return sha256(new TextEncoder().encode("SPR/native-nitro/discovery/v1" + canonicalizeJsonValue(info)));
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
  const decoded = await response.json() as { info: ServiceInfo; evidence: string };
  const { info } = decoded;
  const evidence = requireHex(decoded.evidence);
  const now = BigInt(Date.now());
  const binding = discoveryBinding(info);
  const proofKey = await verifyNativeNitroEvidence(evidence, nonce, binding, pin.pcrs, now);
  await assert.rejects(
    verifyNativeNitroEvidence(evidence, crypto.getRandomValues(new Uint8Array(32)), binding, pin.pcrs, now),
    /BootProofUnverified/,
  );
  const fakeTransport = "00".repeat(info.quorum_public_key.length / 2);
  await assert.rejects(
    verifyNativeNitroEvidence(evidence, nonce, discoveryBinding({ ...info, quorum_public_key: fakeTransport }), pin.pcrs, now),
    /BootProofUnverified/,
  );
  writeFileSync(resolve(directory, pin.releaseId + "-evidence.json"),
    JSON.stringify({ now: String(now), nonce: encodeLowerHex(nonce), binding: encodeLowerHex(binding),
      pcrs: pin.pcrs, proofKey, evidence: decoded.evidence }, null, 2));
  return { info, proofKey };
}

await initializePoseidon();
const originalPin = target("a");
signedPolicy = signPolicy("1", [originalPin]);
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
signedPolicy = signPolicy("1", [{ ...recoveredPin, pcrs: originalPin.pcrs }]);
await assert.rejects(clientFor().address(owner.address), /policy rollback or checkpoint/);
signedPolicy = signPolicy("2", [{ ...recoveredPin, pcrs: originalPin.pcrs }]);
await assert.rejects(clientFor().address(owner.address), /BootProofUnverified/);
const recovered = await checkEvidence(recoveredPin);
assert.notEqual(recovered.info.quorum_public_key, original.info.quorum_public_key);
assert.notEqual(recovered.proofKey, original.proofKey);
const unavailable = { ...recoveredPin, endpoint: new URL("offline/", recoveredPin.endpoint).href };
signedPolicy = signPolicy("3", replacementUrl ? [unavailable, recoveredPin, originalPin] : [unavailable, recoveredPin]);
const restored = clientFor();
const restoredRecipient = await restored.address(owner.address);
assert.deepEqual(restoredRecipient.viewingPublicKey.toBytes(), recipient.viewingPublicKey.toBytes());
assert.deepEqual(restoredRecipient.nullifierPublicKey, recipient.nullifierPublicKey);
assert.deepEqual(await openNote(restored), [amount]);
console.log("Image B rejected the old PCR pin and opened the same note. Both connection keys rotated and both note keys stayed stable.");
if (replacementUrl) {
  writeFileSync(resolve(directory, "before-retire"), "");
  await waitForMarker("old-retired");
  const old = await fetch(new URL("health", originalPin.endpoint), { signal: AbortSignal.timeout(3000) }).catch(() => undefined);
  assert.ok(!old?.ok, "image A was still serving after retirement");
}
signedPolicy = signPolicy("4", [recoveredPin], recoveredPin.custodyEpoch);
assert.deepEqual(await openNote(clientFor()), [amount]);
console.log("The owner reopened the note under the replacement custody epoch.");
signedPolicy = signPolicy("5", [originalPin], originalPin.custodyEpoch);
if (BigInt(recoveredPin.custodyEpoch) > BigInt(originalPin.custodyEpoch)) {
  await assert.rejects(clientFor().address(owner.address), /policy rollback or checkpoint/);
  console.log("A higher-sequence policy could not restore the retired custody epoch.");
}
signedPolicy = signPolicy("1", [originalPin]);
await assert.rejects(clientFor().address(owner.address), /policy rollback or checkpoint/);
console.log("A new SDK client rejected an older signed policy using the stored checkpoint.");
secrets.forEach(secret => secret.fill(0));
server.close();
