import devnet from "../../releases/devnet.json";
import mainnet from "../../releases/mainnet.json";
import mainnetTrust from "../../trust/mainnet.json";
import type { QosIdentityPcrs } from "../attestation/boot-proof.js";
import { decodeDecimalU64 } from "./decimal.js";
import { DecryptionServiceError } from "./error.js";
import type { Network, PinnedReleaseAuthorities, SignedReleasePolicy } from "./types.js";

/** The trust a client pins for one enclave release. */
export type ReleaseTrust = {
  readonly releasePolicy: SignedReleasePolicy;
  readonly releaseAuthorities: PinnedReleaseAuthorities;
  /** Independently pinned PCR0-3 values. Never copy them from discovery or a Boot Proof. */
  readonly qosIdentityPcrs: QosIdentityPcrs;
};

/** The releases a set of per-network files pins; `null` in a file pins none for its network. */
export function pinnedReleases(
  files: Readonly<Record<Network, unknown>>,
): Readonly<Partial<Record<Network, ReleaseTrust>>> {
  return Object.freeze(
    Object.fromEntries(Object.entries(files).filter(([, release]) => release !== null)),
  );
}

export type MainnetTrust = {
  readonly releaseAuthorities: PinnedReleaseAuthorities;
  readonly qosIdentityPcrs: QosIdentityPcrs;
  readonly securityDomainId: string;
  readonly quorumPublicKey: string;
  readonly maximumPolicyLifetimeMs: number;
};

const deployedMainnet = mainnet as SignedReleasePolicy | null;
const pinnedMainnetTrust = mainnetTrust as MainnetTrust | null;

export function bindMainnetRelease(
  releasePolicy: SignedReleasePolicy,
  trust: MainnetTrust | null,
): ReleaseTrust {
  if (!trust) throw new DecryptionServiceError("ReleaseNotPinned", "mainnet trust anchors are unavailable");
  const { policy } = releasePolicy;
  const { releaseAuthorities, qosIdentityPcrs, maximumPolicyLifetimeMs } = trust;
  if (policy.network !== "mainnet" || policy.securityDomainId !== trust.securityDomainId ||
      policy.quorumPublicKey !== trust.quorumPublicKey ||
      !Number.isSafeInteger(releaseAuthorities.threshold) || releaseAuthorities.threshold < 2 ||
      !Number.isSafeInteger(maximumPolicyLifetimeMs) || maximumPolicyLifetimeMs <= 0) {
    throw new DecryptionServiceError("ReleasePolicyInvalid");
  }
  const lifetime = decodeDecimalU64(policy.expiresAtMs) - decodeDecimalU64(policy.validFromMs);
  if (lifetime <= 0n || lifetime > BigInt(maximumPolicyLifetimeMs)) {
    throw new DecryptionServiceError("ReleasePolicyInvalid");
  }
  return structuredClone({ releasePolicy, releaseAuthorities, qosIdentityPcrs });
}

export const DECRYPTION_SERVICE_RELEASES = pinnedReleases({
  devnet,
  mainnet: deployedMainnet && pinnedMainnetTrust
    ? structuredClone({ releasePolicy: deployedMainnet, releaseAuthorities: pinnedMainnetTrust.releaseAuthorities, qosIdentityPcrs: pinnedMainnetTrust.qosIdentityPcrs })
    : null,
});

/** A caller can supply a new mainnet policy; the SDK supplies its independently pinned anchors. */
export function releaseForConnection(network: Network, supplied?: ReleaseTrust): ReleaseTrust {
  if (network === "devnet") return supplied ?? releaseFor(network);
  const policy = supplied?.releasePolicy ?? deployedMainnet;
  if (!policy) throw new DecryptionServiceError("ReleaseNotPinned", "mainnet policy is unavailable");
  return bindMainnetRelease(policy, pinnedMainnetTrust);
}

/** The release `releases` pins for `network`; a network without one is `ReleaseNotPinned`. */
export function releaseFor(network: Network, releases = DECRYPTION_SERVICE_RELEASES): ReleaseTrust {
  const release = Object.hasOwn(releases, network) ? releases[network] : undefined;
  if (release === undefined) {
    throw new DecryptionServiceError("ReleaseNotPinned", `this package pins no ${network} release`);
  }
  return release;
}
