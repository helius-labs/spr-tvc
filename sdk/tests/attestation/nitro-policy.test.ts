import { p256 } from "@noble/curves/p256";
import { describe, expect, it } from "vitest";
import {
  advancesNitroPolicy, nextNitroPublication, nitroCustodySigningDigest, nitroPolicySigningDigest, nitroPublication, validateNitroTrust, verifyNitroPolicy,
  requireRetirementPolicy, verifyPublishedNitroPolicy,
  type NitroPolicy, type NitroPolicyCheckpoint, type NitroTrust,
} from "../../src/attestation/nitro-policy.js";
import { signP256Prehash } from "../../src/crypto/p256.js";
import { encodeLowerHex } from "../../src/protocol/hex.js";

const privateKeys = Array.from({ length: 15 }, (_, index) => new Uint8Array(32).fill(index + 1));
const keys = privateKeys.map(key => encodeLowerHex(p256.getPublicKey(key, false)));
const now = 1_750_000_000_000n;
const trustBase = {
  network: "mainnet",
  securityDomainId: "11".repeat(32),
  noteSeedCommitment: "22".repeat(32),
  threshold: 2,
  keys: keys.slice(0, 3),
  custodyKeys: keys.slice(9, 12),
  minimumSequence: "9",
  minimumCustodyEpoch: "1",
  publications: [
    { bucket: "release-test", region: "eu-north-1", account: "000000000001" },
    { bucket: "release-peer", region: "eu-west-1", account: "000000000002" },
  ],
} satisfies Omit<NitroTrust, "minimumPolicyDigest">;
const binding: NitroPolicy = {
  version: 1,
  action: "activate", recoveryOnly: false,
  network: trustBase.network,
  securityDomainId: trustBase.securityDomainId,
  noteSeedCommitment: trustBase.noteSeedCommitment,
  sequence: "9",
  previousPolicyDigest: "ab".repeat(32),
  minimumCustodyEpoch: "1",
  validFromMs: String(now - 1n),
  expiresAtMs: String(now + 100n),
  targets: [{
    endpoint: "https://slot-a.example.com/",
    releaseId: "generation-9",
    custodyEpoch: "1",
    custodyDigest: "11".repeat(32),
    executableSha256: "33".repeat(32),
    pcrs: { 0: "11".repeat(48), 1: "22".repeat(48), 2: "33".repeat(48), 3: "44".repeat(48), 4: "56".repeat(48) },
  }],
};

function pinned(policy: NitroPolicy, base: Omit<NitroTrust, "minimumPolicyDigest"> = trustBase): NitroTrust {
  return { ...base, minimumSequence: policy.sequence, minimumPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(policy)) };
}
const trust = pinned(binding);

function signatures(policy: NitroPolicy, ...signers: number[]) {
  return signers.map(index => ({
    key: keys[index]!,
    signature: encodeLowerHex(signP256Prehash(privateKeys[index]!, nitroPolicySigningDigest(policy))),
  }));
}
function custodySignatures(policy: NitroPolicy, signers = [9, 10]) {
  return signers.map(index => ({
    key: keys[index]!,
    signature: encodeLowerHex(signP256Prehash(privateKeys[index]!, nitroCustodySigningDigest(policy))),
  }));
}
function manifest(policy: NitroPolicy, ...signers: number[]) {
  return JSON.stringify({ policy, signatures: signatures(policy, ...signers),
    custodySignatures: custodySignatures(policy) });
}

function agreed(checkpoint: NitroPolicyCheckpoint, previousPolicyDigest: string | null) {
  const revision = { checkpoint, previousPolicyDigest };
  return [revision, revision] as const;
}

describe("native Nitro release policy", () => {
  it("matches the operator custody signing digest", () => {
    const policy = { sequence: "1", network: "devnet" } as NitroPolicy;
    expect(encodeLowerHex(nitroCustodySigningDigest(policy))).toBe("8ed7448f3867c9f0f322df52cbcf63866044c8b13032604a4d3f5cfc49547e8a");
  });
  it("authorizes two distinct trusted P-256 signatures over a canonical policy", () => {
    validateNitroTrust(trust);
    const verified = verifyNitroPolicy(manifest(binding, 0, 2), trust, now);
    expect(verified.policy).toEqual(binding);
    expect(verified.checkpoint).toEqual({
      sequence: "9", minimumCustodyEpoch: "1", recoveryOnly: false, digest: encodeLowerHex(nitroPolicySigningDigest(binding)),
    });
    expect(verifyNitroPolicy(manifest(binding, 2, 0), trust, now).checkpoint).toEqual(verified.checkpoint);
  });

  it("requires a pinned quorum and rejects duplicate, malformed or stale signatures", () => {
    for (const invalid of [manifest(binding, 0), manifest(binding, 0, 0), manifest(binding, 0, 3)]) {
      expect(() => verifyNitroPolicy(invalid, trust, now)).toThrow();
    }
    const oldSignatures = signatures(binding, 0, 2);
    expect(() => verifyNitroPolicy(JSON.stringify({
      policy: { ...binding, targets: [{ ...binding.targets[0], endpoint: "https://new.example.com/" }] },
      signatures: oldSignatures, custodySignatures: custodySignatures(binding),
    }), trust, now)).toThrow("InvalidSignature");
    expect(() => validateNitroTrust({ ...trust, keys: [keys[0]!, keys[0]!] })).toThrow();
    expect(() => validateNitroTrust({ ...trust, threshold: 1 })).toThrow();
    expect(() => validateNitroTrust({ ...trust, keys: ["00", keys[1]!] })).toThrow();
  });

  it("bounds rollover signatures and refuses duplicate or invalid signatures outside the pinned roster", () => {
    const signers = [0, 1, 2, 3, 4, 5, 6, 7];
    expect(() => verifyNitroPolicy(manifest(binding, ...signers), trust, now)).not.toThrow();
    expect(() => verifyNitroPolicy(manifest(binding, ...signers, 8), trust, now)).toThrow();
    expect(() => verifyNitroPolicy(manifest(binding, 0, 1, 3, 3), trust, now)).toThrow();
    const [first, second, other] = signatures(binding, 0, 1, 3);
    expect(() => verifyNitroPolicy(JSON.stringify({ policy: binding, custodySignatures: custodySignatures(binding), signatures: [first, second, {
      ...other, signature: first!.signature,
    }] }), trust, now)).toThrow("InvalidSignature");
  });

  it("rejects a conflicting trust domain, seed, network or version, even with valid signatures", () => {
    for (const policy of [
      { ...binding, securityDomainId: "44".repeat(32) },
      { ...binding, noteSeedCommitment: "44".repeat(32) },
      { ...binding, network: "devnet" },
      { ...binding, sequence: "8" },
      { ...binding, sequence: "09" },
      { ...binding, version: 2 },
    ] as const) expect(() => verifyNitroPolicy(manifest(policy as NitroPolicy, 0, 1), trust, now)).toThrow();
  });

  it("preserves recovery-only mode through later releases and emergency revocation", () => {
    const recover = { ...binding, recoveryOnly: true };
    const recoveryTrust = pinned(recover);
    const current = manifest(recover, 0, 1);
    const previousPolicyDigest = encodeLowerHex(nitroPolicySigningDigest(recover));
    const next = { ...recover, sequence: "10", previousPolicyDigest };
    expect(nextNitroPublication(manifest(next, 0, 1), current, recoveryTrust, now)).toBe(true);
    for (const successor of [next, { ...next, action: "revoke", targets: [] } as const]) {
      expect(nextNitroPublication(manifest(successor, 0, 1), current, recoveryTrust, now)).toBe(true);
      const reopened = manifest({ ...successor, recoveryOnly: false }, 0, 1);
      expect(() => nextNitroPublication(reopened, current, recoveryTrust, now)).toThrow();
      expect(() => verifyPublishedNitroPolicy([reopened, current], recoveryTrust, now)).toThrow();
    }
    expect(() => verifyNitroPolicy(manifest(binding, 0, 1), { ...trust, recoveryOnly: true }, now)).toThrow();
    expect(() => verifyNitroPolicy(manifest({ ...binding, recoveryOnly: undefined } as unknown as NitroPolicy, 0, 1), trust, now)).toThrow();
    expect(verifyNitroPolicy(current, { ...recoveryTrust, recoveryOnly: true }, now).checkpoint.recoveryOnly).toBe(true);
  });

  it("checks the inclusive start, exclusive expiration and maximum policy lifetime", () => {
    const signed = manifest(binding, 0, 1);
    expect(() => verifyNitroPolicy(signed, trust, now - 2n)).toThrow();
    expect(() => verifyNitroPolicy(signed, trust, now - 1n)).not.toThrow();
    expect(() => verifyNitroPolicy(signed, trust, now + 100n)).toThrow();
    expect(() => verifyNitroPolicy(manifest({
      ...binding, expiresAtMs: String(now + 7n * 86_400_000n),
    }, 0, 1), trust, now)).toThrow();
  });

  it("requires two custody approvals of the exact activation, independently of the release quorum", () => {
    const approvals = custodySignatures(binding);
    const release = signatures(binding, 0, 1);
    for (const missing of [[], approvals.slice(0, 1), [approvals[0], approvals[0]],
      custodySignatures(binding, [9, 12]), signatures(binding, 9, 10), release]) {
      expect(() => verifyNitroPolicy(JSON.stringify({ policy: binding, signatures: release, custodySignatures: missing }), trust, now))
        .toThrow();
    }
    const changed = { ...binding, targets: [{ ...binding.targets[0]!, releaseId: "different-enclave" }] };
    expect(() => verifyNitroPolicy(JSON.stringify({
      policy: changed, signatures: signatures(changed, 0, 1), custodySignatures: approvals,
    }), trust, now)).toThrow("InvalidSignature");
    expect(() => validateNitroTrust({ ...trust, custodyKeys: [keys[0]!, keys[10]!, keys[11]!] })).toThrow();
    expect(() => validateNitroTrust({ ...trust, custodyKeys: [keys[9]!, keys[9]!, keys[11]!] })).toThrow();
  });

  it("supports an activation approved by both custody rosters during rotation", () => {
    const approvals = custodySignatures(binding, [9, 10, 12, 13]);
    const dual = JSON.stringify({ policy: binding, signatures: signatures(binding, 0, 1), custodySignatures: approvals });
    const incoming = { ...trust, custodyKeys: keys.slice(12, 15) };
    expect(verifyPublishedNitroPolicy([dual, dual], trust, now).policy).toEqual(binding);
    expect(verifyPublishedNitroPolicy([dual, dual], incoming, now).policy).toEqual(binding);
    expect(() => verifyNitroPolicy(manifest(binding, 0, 1), incoming, now)).toThrow();
  });

  it("requires both quorums for a revocation with no targets", () => {
    const revoke = { ...binding, action: "revoke", targets: [] } as const;
    expect(verifyNitroPolicy(manifest(revoke, 0, 1), pinned(revoke), now).policy).toEqual(revoke);
    const oneQuorum = { ...revoke, recoveryOnly: true, minimumCustodyEpoch: "18446744073709551615" };
    expect(() => verifyNitroPolicy(JSON.stringify({
      policy: oneQuorum, signatures: signatures(oneQuorum, 0, 1), custodySignatures: [],
    }), trust, now)).toThrow("ReleasePolicyInvalid");
    expect(() => verifyNitroPolicy(manifest({ ...binding, action: "revoke" }, 0, 1), trust, now)).toThrow();
    expect(() => verifyNitroPolicy(JSON.stringify({
      policy: revoke, signatures: signatures(binding, 0, 1), custodySignatures: custodySignatures(revoke),
    }), trust, now)).toThrow();
  });

  it("rejects unmeasured, ambiguous or insecure routes", () => {
    const first = binding.targets[0]!;
    for (const targets of [
      [],
      [first, first],
      Array.from({ length: 9 }, (_, i) => ({ ...first, endpoint: `https://slot-${i}.example.com/` })),
      [{ ...first, endpoint: "http://127.0.0.1/" }],
      [{ ...first, endpoint: "https://name:pw@example.com/" }],
      [{ ...first, endpoint: "https://example.com/?a=1" }],
      [{ ...first, endpoint: "https://example.com" }],
      [{ ...first, releaseId: "../escape" }],
      [{ ...first, pcrs: { ...first.pcrs, 0: "00".repeat(48) } }],
      [{ ...first, pcrs: { ...first.pcrs, 3: "33".repeat(32) } }],
      [{ ...first, pcrs: { ...first.pcrs, 4: "00".repeat(48) } }],
      [{ ...first, pcrs: { ...first.pcrs, 8: "33".repeat(48) } }],
      [{ ...first, executableSha256: "00".repeat(32) }],
    ]) expect(() => verifyNitroPolicy(manifest({ ...binding, targets }, 0, 1), trust, now)).toThrow();
    const { 0: image, 1: kernel, 2: application, 3: role } = first.pcrs;
    const missingParent = {
      ...first, pcrs: { 0: image, 1: kernel, 2: application, 3: role } as typeof first.pcrs,
    };
    expect(() => verifyNitroPolicy(manifest({ ...binding, targets: [missingParent] }, 0, 1), trust, now))
      .toThrow("InvalidCanonicalJson");
    const devnet = {
      ...binding, network: "devnet", targets: [{ ...first, endpoint: "http://127.0.0.1/" }],
    } as const;
    expect(() => verifyNitroPolicy(manifest(devnet, 0, 1), pinned(devnet, { ...trustBase, network: "devnet" }), now)).not.toThrow();
  });

  it("rejects duplicate JSON fields before applying a valid signature", () => {
    expect(() => verifyNitroPolicy(
      manifest(binding, 0, 1).replace('"sequence":"9"', '"sequence":"1","sequence":"9"'),
      trust, now,
    )).toThrow("DuplicateJsonField");
  });

  it("requires every signed target to meet the policy custody floor", () => {
    const oldTarget = binding.targets[0]!;
    const next: NitroPolicy = {
      ...binding, sequence: "10", minimumCustodyEpoch: "2", previousPolicyDigest: trust.minimumPolicyDigest,
      targets: [{ ...oldTarget, custodyEpoch: "2" }],
    };
    const retired = verifyNitroPolicy(manifest(next, 0, 1), trust, now).checkpoint;
    const old = verifyNitroPolicy(manifest({ ...binding, sequence: "11" }, 0, 1), trust, now).checkpoint;
    expect(advancesNitroPolicy(retired, agreed(old, retired.digest))).toBe(false);
    expect(() => verifyNitroPolicy(manifest({ ...next, targets: [oldTarget] }, 0, 1), trust, now)).toThrow();
    expect(() => verifyNitroPolicy(manifest(binding, 0, 1), { ...trust, minimumCustodyEpoch: "2" }, now)).toThrow();
    expect(() => verifyNitroPolicy(manifest({ ...next, minimumCustodyEpoch: "02" }, 0, 1), trust, now)).toThrow();
  });

  it("accepts identical checkpoints and forward sequences, refusing rollback and equivocation", () => {
    const first = verifyNitroPolicy(manifest(binding, 0, 1), trust, now).checkpoint;
    expect(advancesNitroPolicy(undefined, agreed(first, binding.previousPolicyDigest))).toBe(true);
    expect(advancesNitroPolicy(first, agreed(first, binding.previousPolicyDigest))).toBe(true);
    const next = { ...first, sequence: "10", digest: "aa".repeat(32) };
    expect(advancesNitroPolicy(first, agreed(next, first.digest))).toBe(true);
    expect(advancesNitroPolicy(first, agreed(next, "bb".repeat(32)))).toBe(false);
    expect(advancesNitroPolicy(first, agreed({ ...first, sequence: "8" }, "bb".repeat(32)))).toBe(false);
    expect(advancesNitroPolicy(first, agreed({ ...first, digest: next.digest }, binding.previousPolicyDigest))).toBe(false);
  });

  it("rejects an independently signed fork at and directly after the shipped revision", () => {
    const fork = { ...binding, targets: binding.targets.map(target => ({ ...target, releaseId: "other" })) };
    const disputed = manifest(fork, 0, 1);
    expect(() => verifyPublishedNitroPolicy([disputed, disputed], trust, now)).toThrow("ReleasePolicyInvalid");
    const successor = { ...fork, sequence: "10", previousPolicyDigest: pinned(fork).minimumPolicyDigest };
    const signed = manifest(successor, 0, 1);
    expect(() => verifyPublishedNitroPolicy([signed, signed], trust, now)).toThrow("ReleasePolicyInvalid");
    expect(() => verifyPublishedNitroPolicy([signed, disputed], trust, now)).toThrow("ReleasePolicyInvalid");
    expect(() => validateNitroTrust({ ...trust, minimumPolicyDigest: "00".repeat(32) })).toThrow("ReleasePolicyInvalid");
    const { minimumPolicyDigest, ...missingDigest } = trust;
    expect(() => validateNitroTrust({ ...missingDigest, digest: minimumPolicyDigest } as unknown as NitroTrust))
      .toThrow("UnknownJsonField");
  });

  it("resolves two pinned publication buckets and rejects a shared bucket or owner", () => {
    const [first, second] = trust.publications;
    const publication = nitroPublication(trust, first);
    expect(publication.key).toBe(`spr-release/mainnet/${trust.securityDomainId}/policy.json`);
    expect(publication.url.href).toBe(`https://release-test.s3.eu-north-1.amazonaws.com/${publication.key}`);
    for (const invalid of [{ ...first, bucket: "bad.example" }, { ...first, account: second.account },
      { ...first, bucket: second.bucket }]) {
      expect(() => validateNitroTrust({ ...trust, publications: [invalid, second] })).toThrow();
    }
  });

  it("publishes one signed successor of the current digest, including after the current policy expires", () => {
    const expired = { ...binding, validFromMs: String(now - 1000n), expiresAtMs: String(now - 2n) };
    const expiredTrust = pinned(expired);
    const prior = manifest(expired, 0, 1);
    const successor = { ...binding, sequence: "10", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(expired)) };
    expect(nextNitroPublication(manifest(successor, 0, 1), prior, expiredTrust, now)).toBe(true);
    expect(nextNitroPublication(manifest(successor, 0, 1), manifest(successor, 0, 2), expiredTrust, now)).toBe(false);
    expect(() => nextNitroPublication(manifest({ ...successor, action: "revoke", targets: [] }, 0, 1),
      manifest(successor, 0, 1), expiredTrust, now)).toThrow();
    for (const invalid of [{ ...successor, sequence: "11" }, { ...successor, previousPolicyDigest: "44".repeat(32) }, binding]) {
      expect(() => nextNitroPublication(manifest(invalid, 0, 1), prior, expiredTrust, now)).toThrow();
    }
    const genesis = { ...binding, sequence: "1", previousPolicyDigest: null };
    expect(nextNitroPublication(manifest(genesis, 0, 1), undefined, pinned(genesis), now)).toBe(true);
    expect(() => nextNitroPublication(manifest(successor, 0, 1), undefined, trust, now)).toThrow();
  });

  it("rotates signer pins without resetting the publication or its sequence", () => {
    const successor = { ...binding, sequence: "10", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(binding)) };
    const previous = manifest(binding, 0, 1);
    const rotated = { ...trust, keys: keys.slice(2, 4) };
    const next = manifest(successor, 2, 3);
    expect(() => nextNitroPublication(next, previous, rotated, now)).toThrow();
    expect(nextNitroPublication(next, previous, rotated, now, trust)).toBe(true);
    expect(nextNitroPublication(next, next, rotated, now, trust)).toBe(false);
    expect(() => nextNitroPublication(next, previous, rotated, now, {
      ...trust, publications: [trust.publications[0], { ...trust.publications[1], account: "000000000003" }],
    })).toThrow();
  });

  it("rolls disjoint signer rosters through a dual-signed revision on both buckets", () => {
    const original = { ...trust, keys: keys.slice(0, 2) };
    const head = manifest(binding, 0, 1);
    const bridge: NitroPolicy = {
      ...binding, sequence: "10", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(binding)),
    };
    const rotated = pinned(bridge, { ...trustBase, keys: keys.slice(2, 4) });
    const dual = manifest(bridge, 0, 1, 2, 3);
    expect(nextNitroPublication(dual, head, original, now)).toBe(true);
    expect(verifyPublishedNitroPolicy([dual, head], original, now)).toMatchObject({ policy: bridge, agreed: false });
    expect(() => verifyPublishedNitroPolicy([dual, head], rotated, now)).toThrow();

    const oldView = verifyPublishedNitroPolicy([dual, dual], original, now);
    const newView = verifyPublishedNitroPolicy([dual, dual], rotated, now);
    expect(newView.checkpoint).toEqual(oldView.checkpoint);
    expect(newView.agreed).toBe(true);
    expect(() => verifyNitroPolicy(manifest(bridge, 0, 2, 3), original, now)).toThrow();
    expect(() => verifyNitroPolicy(manifest(bridge, 0, 1, 2), rotated, now)).toThrow();

    const next: NitroPolicy = { ...bridge, sequence: "11", previousPolicyDigest: newView.checkpoint.digest };
    const newHead = manifest(next, 2, 3);
    expect(nextNitroPublication(newHead, dual, rotated, now)).toBe(true);
    expect(verifyPublishedNitroPolicy([newHead, dual], rotated, now)).toMatchObject({ policy: next, agreed: false });
    expect(() => verifyPublishedNitroPolicy([newHead, dual], original, now)).toThrow();
  });

  it("requires the same current signed activation at both buckets before retirement", () => {
    const replacement = { ...binding.targets[0]!, custodyEpoch: "2", custodyDigest: "77".repeat(32) };
    const policy = { ...binding, minimumCustodyEpoch: "2", targets: [replacement] };
    const retire = (candidate: NitroPolicy, time = now) => {
      const envelope = manifest(candidate, 0, 1);
      const published = verifyPublishedNitroPolicy([envelope, envelope], pinned(candidate), time);
      requireRetirementPolicy(published, "2", replacement.custodyDigest);
    };
    expect(() => retire(policy)).not.toThrow();
    for (const unsafe of [
      { ...policy, minimumCustodyEpoch: "1" },
      { ...policy, action: "revoke", targets: [] } as const,
      { ...policy, targets: [{ ...replacement, custodyEpoch: "3" }] },
      { ...policy, targets: [{ ...replacement, custodyDigest: "88".repeat(32) }] },
    ]) expect(() => retire(unsafe)).toThrow();
    expect(() => retire(policy, now + 100n)).toThrow();
    const mismatched = verifyPublishedNitroPolicy([manifest(policy, 0, 1), manifest(policy, 1, 2)], pinned(policy), now);
    expect(mismatched.agreed).toBe(true);
    expect(() => requireRetirementPolicy(mismatched, "2", replacement.custodyDigest)).toThrow();
    const successor = { ...policy, sequence: "10", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(binding)) };
    const split = verifyPublishedNitroPolicy([manifest(successor, 0, 1), manifest(binding, 0, 1)], trust, now);
    expect(split.policy).toEqual(successor);
    expect(() => requireRetirementPolicy(split, "2", replacement.custodyDigest)).toThrow();
  });

  it("allows the primary to advance if the mirror serves its predecessor, even when that predecessor expired", () => {
    const prior = { ...binding, validFromMs: String(now - 1000n), expiresAtMs: String(now - 2n) };
    const next = { ...binding, sequence: "10", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(prior)) };
    const currentTrust = pinned(next);
    const heads = [manifest(next, 0, 1), manifest(prior, 0, 1)] as const;
    expect(verifyPublishedNitroPolicy(heads, currentTrust, now)).toMatchObject({ policy: next, agreed: false });
    expect(verifyPublishedNitroPolicy([heads[0], manifest(next, 0, 2)], currentTrust, now)).toMatchObject({ policy: next, agreed: true });
  });

  it("fails closed when the mirror is ahead even if both policies are valid", () => {
    const next = { ...binding, sequence: "10", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(binding)) };
    expect(() => verifyPublishedNitroPolicy([manifest(binding, 0, 1), manifest(next, 0, 1)], trust, now))
      .toThrow("ReleasePolicyInvalid");
  });

  it("refuses gaps, forks, unauthenticated heads and an unusable successor without falling back", () => {
    const next = { ...binding, sequence: "10", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(binding)) };
    const current = manifest(binding, 0, 1);
    for (const other of [
      manifest({ ...binding, action: "revoke", targets: [] }, 0, 1),
      manifest({ ...next, sequence: "11" }, 0, 1),
      manifest({ ...next, previousPolicyDigest: "66".repeat(32) }, 0, 1),
      manifest(next, 0, 3),
      manifest({ ...next, expiresAtMs: String(now) }, 0, 1),
      manifest({ ...next, validFromMs: String(now + 1n) }, 0, 1),
    ]) expect(() => verifyPublishedNitroPolicy([other, current], trust, now)).toThrow();
    expect(() => verifyPublishedNitroPolicy([current, current], { ...trust, minimumSequence: "10" }, now)).toThrow();
  });

  it("rejects competing custody records for the same epoch within and across policy revisions", () => {
    const target = binding.targets[0]!;
    const competing = { ...target, endpoint: "https://slot-b.example.com/", custodyDigest: "bb".repeat(32) };
    expect(() => verifyNitroPolicy(manifest({ ...binding, targets: [target, competing] }, 0, 1), trust, now)).toThrow();
    const next = { ...binding, sequence: "10", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(binding)) };
    expect(() => nextNitroPublication(manifest({ ...next, targets: [competing] }, 0, 1), manifest(binding, 0, 1), trust, now)).toThrow();
  });
});
