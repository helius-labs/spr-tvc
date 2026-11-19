import devnet from "../decryption-service/releases/devnet.json";
import mainnet from "../decryption-service/releases/mainnet.json";
import type { QosIdentityPcrs } from "../verify/index.js";
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

export const DECRYPTION_SERVICE_RELEASES = pinnedReleases({ devnet, mainnet });

/** The release `releases` pins for `network`; a network without one is `ReleaseNotPinned`. */
export function releaseFor(network: Network, releases = DECRYPTION_SERVICE_RELEASES): ReleaseTrust {
  const release = Object.hasOwn(releases, network) ? releases[network] : undefined;
  if (release === undefined) {
    throw new DecryptionServiceError("ReleaseNotPinned", `this package pins no ${network} release`);
  }
  return release;
}
