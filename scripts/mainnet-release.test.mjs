import assert from "node:assert/strict";
import { test } from "node:test";

import { requireCandidateApp, requireMainnetQuorum, verifyMainnetImage, verifyMainnetPolicy } from "./mainnet-release.mjs";

test("mainnet verifies the digest from the publisher on the exact reviewed commit", () => {
  const commit = "1".repeat(40);
  const registry = "ghcr.io/helius-labs/spr-tvc-decryption-service";
  const image = `${registry}:decryption-service-mainnet-${commit.slice(0, 12)}@sha256:${"2".repeat(64)}`;
  assert.throws(() => verifyMainnetImage(image, registry, commit.slice(0, 12)), /full commit/);
  assert.throws(() => verifyMainnetImage(image, registry, "3".repeat(40)), /immutable image digest/);
  assert.throws(() => verifyMainnetImage(image, registry, commit, () => { throw Error("unattested"); }), /unattested/);
  verifyMainnetImage(image, registry, commit, (command, args) => {
    assert.equal(command, "gh");
    assert.deepEqual(args, [
      "attestation", "verify", `oci://${registry}@sha256:${"2".repeat(64)}`, "--repo", "helius-labs/spr-tvc",
      "--signer-workflow", "helius-labs/spr-tvc/.github/workflows/publish-enclave-image.yml",
      "--source-ref", "refs/heads/main", "--source-digest", commit,
      "--predicate-type", "https://slsa.dev/provenance/v1",
    ]);
  });
});

test("a candidate can resume its own app and cannot replace a serving release", () => {
  assert.doesNotThrow(() => requireCandidateApp(null, undefined));
  assert.doesNotThrow(() => requireCandidateApp("candidate", "candidate"));
  assert.throws(() => requireCandidateApp("serving", undefined), /separate Turnkey app/);
  assert.throws(() => requireCandidateApp("serving", "candidate"), /separate Turnkey app/);
});

test("mainnet release cannot change the pinned root or share the devnet key", () => {
  const cfg = { appId: "mainnet", securityDomainId: "mainnet" };
  const app = { quorumPublicKey: "00".repeat(130) };
  const trust = { quorumPublicKey: app.quorumPublicKey, securityDomainId: cfg.securityDomainId };
  const devnet = { appId: "devnet", securityDomainId: "devnet", quorumPublicKey: "11".repeat(130) };
  assert.doesNotThrow(() => requireMainnetQuorum(cfg, app, trust, devnet));
  assert.throws(() => requireMainnetQuorum(cfg, app, null, devnet), /independently pinned/);
  assert.throws(() => requireMainnetQuorum(cfg, app, trust, devnet, {
    securityDomainId: cfg.securityDomainId, quorumPublicKey: "33".repeat(130),
  }), /separate recipient migration/);
  assert.throws(() => requireMainnetQuorum(cfg, { quorumPublicKey: "22".repeat(130) }, trust, devnet), /independently pinned/);
  assert.throws(() => requireMainnetQuorum(cfg, app, trust, { ...devnet, quorumPublicKey: app.quorumPublicKey }), /separate apps/);
  assert.throws(() => requireMainnetQuorum({ ...cfg, appId: devnet.appId }, app, trust, devnet), /separate apps/);
});

test("policy publication only verifies signatures for the attested candidate", () => {
  const policy = { acceptedManifestDigests: ["candidate"] };
  const authorities = {};
  const trust = { releaseAuthorities: authorities };
  const signed = { policy };
  const now = 1n;
  const sdk = {
    bindMainnetRelease: (_, pinned) => pinned,
    policySigningDigest: (value) => Buffer.from(JSON.stringify(value)),
    verifySignedReleasePolicy: (...args) => assert.deepEqual(args, [signed, authorities, "mainnet", now]),
  };
  assert.doesNotThrow(() => verifyMainnetPolicy(signed, policy, trust, sdk, now));
  assert.throws(
    () => verifyMainnetPolicy(signed, { acceptedManifestDigests: ["other"] }, trust, sdk, now),
    /does not match the attested candidate/,
  );
});
