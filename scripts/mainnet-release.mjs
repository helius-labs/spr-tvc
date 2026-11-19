import { execFileSync } from "node:child_process";

const REPOSITORY = "helius-labs/spr-tvc";
const WORKFLOW = `${REPOSITORY}/.github/workflows/publish-enclave-image.yml`;

export function verifyMainnetImage(image, repository, sourceCommit, run = execFileSync) {
  if (!/^[0-9a-f]{40}$/.test(sourceCommit ?? "")) {
    throw new Error("mainnet requires --source-commit with the reviewed full commit hash");
  }
  const tag = `${repository}:decryption-service-mainnet-${sourceCommit.slice(0, 12)}@sha256:`;
  if (!image?.startsWith(tag) || !/^[0-9a-f]{64}$/.test(image.slice(tag.length))) {
    throw new Error("mainnet image must name the reviewed source commit and an immutable image digest");
  }
  const subject = `oci://${repository}@sha256:${image.slice(tag.length)}`;
  run("gh", [
    "attestation", "verify", subject, "--repo", REPOSITORY,
    "--signer-workflow", WORKFLOW, "--source-ref", "refs/heads/main",
    "--source-digest", sourceCommit, "--predicate-type", "https://slsa.dev/provenance/v1",
  ], { stdio: ["ignore", "ignore", "inherit"] });
}

export function requireCandidateApp(liveDeployment, recordedDeployment) {
  if (liveDeployment && liveDeployment !== recordedDeployment) {
    throw new Error("stage mainnet releases in a separate Turnkey app with its own ingress");
  }
}

export function requireMainnetQuorum(cfg, app, trust, devnet, previous) {
  if (!trust || cfg.securityDomainId !== trust.securityDomainId ||
      app.quorumPublicKey !== trust.quorumPublicKey ||
      !/^[0-9a-f]{260}$/.test(trust.quorumPublicKey ?? "")) {
    throw new Error("mainnet app must match the independently pinned Quorum key and security domain");
  }
  if (previous && (previous.quorumPublicKey !== trust.quorumPublicKey || previous.securityDomainId !== trust.securityDomainId)) {
    throw new Error("changing the current Quorum domain requires a separate recipient migration");
  }
  if (cfg.appId === devnet.appId || cfg.securityDomainId === devnet.securityDomainId ||
      app.quorumPublicKey === devnet.quorumPublicKey) {
    throw new Error("mainnet and devnet require separate apps, security domains, and Quorum keys");
  }
}

export function signableMainnetPolicy(policy, trust, sdk) {
  const unsigned = { policy, authoritySetId: trust.releaseAuthorities.authoritySetId, signatures: [] };
  sdk.bindMainnetRelease(unsigned, trust);
  return { policy, authoritySetId: unsigned.authoritySetId, digest: Buffer.from(sdk.policySigningDigest(policy)).toString("hex") };
}

export function verifyMainnetPolicy(signed, expected, trust, sdk, nowMs) {
  const approved = sdk.bindMainnetRelease(signed, trust);
  if (!Buffer.from(sdk.policySigningDigest(expected)).equals(Buffer.from(sdk.policySigningDigest(signed.policy)))) {
    throw new Error("signed mainnet policy does not match the attested candidate");
  }
  sdk.verifySignedReleasePolicy(signed, approved.releaseAuthorities, "mainnet", nowMs);
}
