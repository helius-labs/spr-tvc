// Covers INV-17 (strict JSON/UTF-8 manifest envelopes, approved manifest-set signatures, debug/env refusal).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { sha256 } from "@noble/hashes/sha256";

import { approvedManifestSha256 } from "../../src/attestation/manifest.js";
import { qosJsonHash } from "../../src/attestation/qos-json.js";
import type { TurnkeyBootProofWire } from "../../src/attestation/turnkey.js";
import type { QosIdentityPcrs } from "../../src/attestation/boot-proof.js";
import type { ReleasePolicy } from "../../src/wire/types.js";
import { encodeLowerHex } from "../../src/wire/hex.js";

const FIXTURE = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../decryption-service/tests/fixtures/qos-0.12.1-manifest-envelope.json",
);
const MANIFEST_SHA256 = "016748a03b94269ade9b75c7b4231a2940cc3c85aabade226a956ea80ab374b0";

type Envelope = {
  manifest: {
    version: string;
    namespace: { name: string; nonce: string | number; quorumKey: string };
    manifestSet: { threshold: string | number; members: { alias: string; pubKey: string }[] };
    enclave: { pcr0: string; pcr1: string; pcr2: string; pcr3: string };
    pivot: { debugMode: boolean; env?: Record<string, string> };
  };
  manifestSetApprovals: unknown[];
};

function load(): Envelope {
  return JSON.parse(readFileSync(FIXTURE, "utf8")) as Envelope;
}

function policyFor(envelope: Envelope): ReleasePolicy {
  const { namespace, manifestSet } = envelope.manifest;
  return {
    version: 1,
    network: "devnet",
    securityDomainId: "00".repeat(32),
    namespace: namespace.name,
    manifestSet: {
      threshold: Number(manifestSet.threshold),
      members: manifestSet.members.map((member) => ({
        alias: member.alias,
        publicKey: member.pubKey,
      })),
    },
    minimumManifestNonce: "0",
    quorumKeyId: "quorum",
    quorumKeyEpoch: "1",
    quorumPublicKey: namespace.quorumKey,
    allowedOperations: [],
    maxEncryptedRequestBytes: 1,
    maxEncryptedResponseBytes: 1,
    turnkeyTrustRootId: "aws-nitro-root-g1",
    validFromMs: "0",
    expiresAtMs: "1",
    revocationEpoch: "0",
  };
}

function pcrsFor(envelope: Envelope): QosIdentityPcrs {
  const { enclave } = envelope.manifest;
  return { 0: enclave.pcr0, 1: enclave.pcr1, 2: enclave.pcr2, 3: enclave.pcr3 };
}

function boot(envelope: unknown): TurnkeyBootProofWire {
  return {
    qosManifestEnvelopeB64: Buffer.from(JSON.stringify(envelope)).toString("base64"),
  } as TurnkeyBootProofWire;
}

describe("QOS canonical JSON", () => {
  it("matches the published vectors", () => {
    expect(encodeLowerHex(qosJsonHash({}))).toBe(
      "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    );
    expect(encodeLowerHex(qosJsonHash({ name: "test", threshold: "3", version: "1" }))).toBe(
      "898eaf2263b3ca34a9fb0b59615a16e5819b43c53fabc44396f92128f72ccc7e",
    );
    expect(encodeLowerHex(qosJsonHash({ data: "deadbeef" }))).toBe(
      "03fe564ceddcb54a7a742bd7a4db57318a068cecd22ae44435ce68d35e754e13",
    );
    expect(encodeLowerHex(sha256(new TextEncoder().encode('{"threshold":"1"}')))).toBe(
      encodeLowerHex(qosJsonHash({ threshold: 1 })),
    );
  });

  it("rejects lone surrogates in object keys and values", () => {
    expect(() => qosJsonHash({ a: "\ud800" })).toThrow();
    expect(() => qosJsonHash({ ["\ud800"]: "a" })).toThrow();
  });
});

describe("approved manifest", () => {
  const envelope = load();
  const policy = policyFor(envelope);
  const pcrs = pcrsFor(envelope);

  it("accepts the fixture envelope the manifest set signed", () => {
    expect(encodeLowerHex(qosJsonHash(envelope.manifest))).toBe(MANIFEST_SHA256);
    expect(approvedManifestSha256(boot(envelope), policy, pcrs)).toBe(MANIFEST_SHA256);
  });

  it("rejects a mutated manifest, a missing signature, a foreign set, debug mode, and non-empty env", () => {
    const mutated = structuredClone(envelope);
    mutated.manifest.namespace.name = "other-namespace";
    expect(() => approvedManifestSha256(boot(mutated), policy, pcrs)).toThrow(
      "BootProofUnverified: manifest",
    );

    const missing = structuredClone(envelope);
    missing.manifestSetApprovals = [];
    expect(() => approvedManifestSha256(boot(missing), policy, pcrs)).toThrow(
      "BootProofUnverified: manifest",
    );

    const foreign = structuredClone(policy);
    foreign.manifestSet = {
      ...foreign.manifestSet,
      members: foreign.manifestSet.members.map((member) => ({ ...member, alias: "someone-else" })),
    };
    expect(() => approvedManifestSha256(boot(envelope), foreign, pcrs)).toThrow(
      "BootProofUnverified: manifest",
    );

    const wrongVersion = structuredClone(envelope);
    wrongVersion.manifest.version = "v1";
    expect(() => approvedManifestSha256(boot(wrongVersion), policy, pcrs)).toThrow(
      "BootProofUnverified: manifest",
    );

    const debug = structuredClone(envelope);
    debug.manifest.pivot.debugMode = true;
    expect(() => approvedManifestSha256(boot(debug), policy, pcrs)).toThrow(
      "BootProofUnverified: manifest",
    );

    const withEnv = structuredClone(envelope);
    withEnv.manifest.pivot.env = { FOO: "bar" };
    expect(() => approvedManifestSha256(boot(withEnv), policy, pcrs)).toThrow(
      "BootProofUnverified: manifest",
    );

    const rawJson = JSON.stringify(envelope);
    const duplicateKeyJson = rawJson.replace('"version":"v2"', '"version":"v2","version":"v2"');
    const duplicateBoot = {
      qosManifestEnvelopeB64: Buffer.from(duplicateKeyJson).toString("base64"),
    } as TurnkeyBootProofWire;
    expect(() => approvedManifestSha256(duplicateBoot, policy, pcrs)).toThrow(
      "BootProofUnverified: manifest",
    );

    const invalidUtf8Boot = {
      qosManifestEnvelopeB64: Buffer.from([0xff, 0xfe, 0xfd]).toString("base64"),
    } as TurnkeyBootProofWire;
    expect(() => approvedManifestSha256(invalidUtf8Boot, policy, pcrs)).toThrow(
      "BootProofUnverified: manifest",
    );
  });
});
