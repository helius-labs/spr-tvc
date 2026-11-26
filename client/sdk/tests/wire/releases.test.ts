import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { p256 } from "@noble/curves/p256";
import { describe, expect, it } from "vitest";

import { assertExactObjectKeys } from "../../src/wire/json.js";
import { signP256Prehash } from "../../src/crypto/p256.js";
import { policySigningDigest, verifySignedReleasePolicy } from "../../src/attestation/release-policy.js";
import { MAX_ENCRYPTED_REQUEST_BYTES } from "../../src/wire/constants.js";
import { encodeLowerHex } from "../../src/wire/hex.js";
import { DECRYPTION_SERVICE_RELEASES as RELEASES, releaseFor, type ReleaseTrust } from "../../src/wire/releases.js";
import type { Network, ReleasePolicy } from "../../src/wire/types.js";
import { fixtureManifestSet } from "../support/manifest-set.js";

const RELEASES_DIR = join(dirname(fileURLToPath(import.meta.url)), "../../releases");
const NETWORKS: readonly Network[] = ["devnet", "mainnet"];
const POLICY_KEYS = [
  "version",
  "network",
  "securityDomainId",
  "namespace",
  "manifestSet",
  "minimumManifestNonce",
  "quorumKeyId",
  "quorumKeyEpoch",
  "quorumPublicKey",
  "allowedOperations",
  "maxEncryptedRequestBytes",
  "maxEncryptedResponseBytes",
  "turnkeyTrustRootId",
  "validFromMs",
  "expiresAtMs",
  "revocationEpoch",
] as const;

/**
 * A pinned release file for `network`, as a client takes it: exactly the
 * three parts, a policy of exactly the protocol's fields signed by the pinned
 * authorities for `network` and in force at `nowMs`, and four PCRs.
 */
function verifyReleaseFile(value: unknown, network: Network, nowMs: bigint): ReleaseTrust {
  assertExactObjectKeys(value, ["releasePolicy", "releaseAuthorities", "qosIdentityPcrs"], "ReleasePolicyInvalid");
  const release = value as ReleaseTrust;
  assertExactObjectKeys(release.releasePolicy, ["policy", "authoritySetId", "signatures"], "ReleasePolicyInvalid");
  assertExactObjectKeys(release.releasePolicy.policy, POLICY_KEYS, "ReleasePolicyInvalid");
  verifySignedReleasePolicy(release.releasePolicy, release.releaseAuthorities, network, nowMs);
  assertExactObjectKeys(release.qosIdentityPcrs, ["0", "1", "2", "3"], "ReleasePolicyInvalid");
  for (const pcr of Object.values(release.qosIdentityPcrs)) expect(pcr).toMatch(/^[0-9a-f]{96}$/);
  return release;
}

describe("the committed release files", () => {
  const files = readdirSync(RELEASES_DIR).sort();

  it("are one per network", () => {
    expect(files).toEqual(NETWORKS.map((network) => `${network}.json`));
  });

  it.each(NETWORKS)("%s pins nothing, or a release that verifies for it", (network) => {
    const pinned = JSON.parse(readFileSync(join(RELEASES_DIR, `${network}.json`), "utf8")) as unknown;
    if (pinned === null) {
      expect(Object.hasOwn(RELEASES, network)).toBe(false);
      expect(() => releaseFor(network)).toThrowError(/ReleaseNotPinned/);
      return;
    }
    const bundled = releaseFor(network);
    const release = verifyReleaseFile(bundled, network, BigInt(Date.now()));
    expect(release.releasePolicy.policy.network).toBe(network);
    expect(network === "mainnet" ? release.releasePolicy : release).toEqual(pinned);
  });
});

describe("a release file", () => {
  const authority = p256.utils.randomPrivateKey();
  const policy: ReleasePolicy = {
    version: 1,
    network: "devnet",
    securityDomainId: "33".repeat(32),
    namespace: "fixture-namespace",
    manifestSet: fixtureManifestSet,
    minimumManifestNonce: "0",
    quorumKeyId: "quorum",
    quorumKeyEpoch: "1",
    quorumPublicKey: "04".repeat(130),
    allowedOperations: ["ServicePublicKeys", "ServiceDecrypt"],
    maxEncryptedRequestBytes: MAX_ENCRYPTED_REQUEST_BYTES,
    maxEncryptedResponseBytes: MAX_ENCRYPTED_REQUEST_BYTES,
    turnkeyTrustRootId: "aws-nitro-root-g1",
    validFromMs: "1700000000000",
    expiresAtMs: "1900000000000",
    revocationEpoch: "0",
  };
  const file = (signed: ReleasePolicy, extra: Record<string, unknown> = {}) => ({
    releasePolicy: {
      policy: signed,
      authoritySetId: "set",
      signatures: [{ keyId: "authority", signature: encodeLowerHex(signP256Prehash(authority, policySigningDigest(signed))) }],
    },
    releaseAuthorities: {
      authoritySetId: "set",
      threshold: 1,
      keys: [{ keyId: "authority", publicKey: encodeLowerHex(p256.getPublicKey(authority, false)) }],
      minimumRevocationEpoch: "0",
    },
    qosIdentityPcrs: { 0: "aa".repeat(48), 1: "bb".repeat(48), 2: "cc".repeat(48), 3: "dd".repeat(48) },
    ...extra,
  });
  const now = 1_800_000_000_000n;

  it("verifies for the network it names and no other", () => {
    expect(verifyReleaseFile(file(policy), "devnet", now).releasePolicy.policy).toEqual(policy);
    expect(() => verifyReleaseFile(file(policy), "mainnet", now)).toThrowError(/NetworkMismatch/);
  });

  it.each([undefined, NaN, 0, 1.5, "1", 2, 256])("rejects a malformed or impossible authority threshold %s", (threshold) => {
    const signed = file(policy);
    const release = { ...signed, releaseAuthorities: { ...signed.releaseAuthorities, threshold } };
    expect(() => verifyReleaseFile(release, "devnet", now)).toThrowError(/ReleasePolicyInvalid/);
  });

  it("rejects the same authority key under two IDs", () => {
    const signed = file(policy);
    const key = signed.releaseAuthorities.keys[0]!;
    signed.releaseAuthorities.keys.push({ ...key, keyId: "alias" });
    expect(() => verifyReleaseFile(signed, "devnet", now)).toThrowError(/ReleasePolicyInvalid/);
  });

  it("rejects noncanonical decimals in a signed policy and its authority set", () => {
    const signed = file({ ...policy, revocationEpoch: "0x0" });
    expect(() => verifyReleaseFile(signed, "devnet", now)).toThrowError("InvalidDecimal");
    const noncanonical = file(policy);
    noncanonical.releaseAuthorities.minimumRevocationEpoch = "00";
    expect(() => verifyReleaseFile(noncanonical, "devnet", now)).toThrowError("InvalidDecimal");
  });

  it("is refused tampered, expired, in another shape, or with a field the protocol does not have", () => {
    const tampered = file(policy);
    tampered.releasePolicy.policy = { ...policy, namespace: "other" };
    expect(() => verifyReleaseFile(tampered, "devnet", now)).toThrowError(/InvalidSignature/);
    tampered.releasePolicy.policy = { ...policy, namespace: "\ud800" };
    expect(() => verifyReleaseFile(tampered, "devnet", now)).toThrowError(/InvalidCanonicalJson/);
    expect(() => verifyReleaseFile(file(policy), "devnet", 1_950_000_000_000n)).toThrowError(/ExpiredRequest/);
    expect(() => verifyReleaseFile(file(policy, { extra: true }), "devnet", now)).toThrowError(/UnknownJsonField/);
    const withEnvironment = { ...policy, environment: "development" } as unknown as ReleasePolicy;
    expect(() => verifyReleaseFile(file(withEnvironment), "devnet", now)).toThrowError(/UnknownJsonField/);
  });
});
