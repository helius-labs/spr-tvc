import { p256 } from "@noble/curves/p256";
import { describe, expect, it } from "vitest";

import { policySigningDigest, verifySignedReleasePolicy } from "../attestation/release-policy.js";
import { signP256Prehash } from "../crypto/p256.js";
import { MAX_ENCRYPTED_REQUEST_BYTES } from "./constants.js";
import { encodeLowerHex } from "./hex.js";
import { bindMainnetRelease, releaseForConnection, type MainnetTrust } from "./releases.js";
import type { ReleasePolicy, SignedReleasePolicy } from "./types.js";

const now = 1_800_000_000_000n;
const secrets = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)];
const publicKeys = secrets.map((secret) => encodeLowerHex(p256.getPublicKey(secret, false)));
const trust: MainnetTrust = {
  releaseAuthorities: {
    authoritySetId: "mainnet",
    threshold: 2,
    minimumRevocationEpoch: "2",
    keys: publicKeys.map((publicKey, i) => ({ keyId: String(i), publicKey })),
  },
  qosIdentityPcrs: { 0: "11".repeat(48), 1: "11".repeat(48), 2: "11".repeat(48), 3: "11".repeat(48) },
  securityDomainId: "33".repeat(32),
  quorumPublicKey: publicKeys.join(""),
  maximumPolicyLifetimeMs: 60_000,
};
const policy: ReleasePolicy = {
  version: 1, network: "mainnet", releaseId: "mainnet-candidate",
  securityDomainId: trust.securityDomainId, quorumPublicKey: trust.quorumPublicKey,
  quorumKeyId: "quorum", quorumKeyEpoch: "1", revocationEpoch: "2",
  acceptedManifestDigests: ["aa".repeat(32)], acceptedExecutableDigests: ["bb".repeat(32)],
  allowedOperations: ["ServicePublicKeys", "ServiceDecrypt"],
  maxEncryptedRequestBytes: MAX_ENCRYPTED_REQUEST_BYTES, maxEncryptedResponseBytes: MAX_ENCRYPTED_REQUEST_BYTES,
  turnkeyTrustRootId: "aws-nitro-root-g1",
  validFromMs: String(now - 60_000n), expiresAtMs: String(now),
};

function signed(value = policy): SignedReleasePolicy {
  return {
    policy: value,
    authoritySetId: trust.releaseAuthorities.authoritySetId,
    signatures: secrets.map((key, i) => ({
      keyId: String(i),
      signature: encodeLowerHex(signP256Prehash(key, policySigningDigest(value))),
    })),
  };
}

function verify(signedPolicy: SignedReleasePolicy, anchors = trust, time = now) {
  const pinned = bindMainnetRelease(signedPolicy, anchors);
  verifySignedReleasePolicy(pinned.releasePolicy, pinned.releaseAuthorities, "mainnet", time);
}

describe("mainnet pins", () => {
  it("requires both distinct pinned signatures and the current revocation epoch", () => {
    const valid = signed();
    expect(() => verify(valid)).not.toThrow();
    expect(() => verify({ ...valid, signatures: valid.signatures.slice(0, 1) })).toThrow(/ReleasePolicyInvalid/);
    expect(() => verify(signed({ ...policy, revocationEpoch: "1" }))).toThrow(/ReleasePolicyInvalid/);
    expect(() => verify(valid, trust, now + 1n)).toThrow(/ExpiredRequest/);
  });

  it("requires the independently pinned Quorum key, domain, and policy lifetime", () => {
    for (const value of [
      { ...policy, quorumPublicKey: publicKeys[1]! + publicKeys[0]! },
      { ...policy, securityDomainId: "00".repeat(32) },
      { ...policy, expiresAtMs: String(now + 1n) },
    ]) expect(() => verify(signed(value))).toThrow(/ReleasePolicyInvalid/);
    expect(() => verify(signed(), {
      ...trust, releaseAuthorities: { ...trust.releaseAuthorities, threshold: 1 },
    })).toThrow(/ReleasePolicyInvalid/);
  });

  it("does not use caller-supplied trust anchors when no mainnet anchors ship", () => {
    const supplied = { releasePolicy: signed(), releaseAuthorities: trust.releaseAuthorities, qosIdentityPcrs: trust.qosIdentityPcrs };
    expect(() => bindMainnetRelease(supplied.releasePolicy, null)).toThrow(/ReleaseNotPinned/);
    // An untrusted bundle alone can never establish the independently compiled trust anchors.
    expect(() => releaseForConnection("mainnet", supplied)).toThrow();
  });
});
