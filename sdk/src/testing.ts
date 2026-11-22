import { sha256 } from "@noble/hashes/sha256";
import { isAddress } from "@solana/kit";

import { connectLocalUnattestedTvc } from "./connection/local-connection.js";
import { sessionFromConnector } from "./connection/session.js";
import type { DecryptionServiceTransport } from "./connection/http.js";
import { decryptionServiceFromSession, type DecryptionService } from "./client/decryption.js";
import { DecryptionServiceError } from "./protocol/error.js";
import { encodeLowerHex } from "./protocol/hex.js";
import { genesisHashForNetwork, requireNetwork } from "./protocol/network.js";
import type { Network, OperationKind } from "./protocol/types.js";
import localTestkit from "../../tests/fixtures/local-testkit.json";

export type { QosIdentityPcrs } from "./attestation/boot-proof.js";
export type { TurnkeyBootProofWire } from "./attestation/turnkey.js";
export { fetchLiveServiceInfo, verifyLiveReplica, type VerifyLiveReplicaInput } from "./connection/connect.js";

const encoder = new TextEncoder();
const digest = (label: string) => encodeLowerHex(sha256(encoder.encode(label)));

export function createLocalDecryptionService(config: {
  readonly network: Network;
  readonly endpoint: URL;
  readonly genesisHash: string;
  readonly transport?: DecryptionServiceTransport;
}): DecryptionService {
  const { genesisHash, endpoint, transport } = config;
  const network = requireNetwork(config.network);
  if (!isAddress(genesisHash) || [
    genesisHashForNetwork("mainnet"), genesisHashForNetwork("devnet"),
    "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY", // Solana testnet.
  ].includes(genesisHash)) throw new DecryptionServiceError("PaymentNetworkMismatch");
  if (localTestkit.version !== 1) throw new Error("unsupported local testkit fixture");
  return decryptionServiceFromSession(sessionFromConnector((signal) =>
    connectLocalUnattestedTvc({
      network,
      backend: { endpoint },
      expectedReleaseId: localTestkit.releaseId,
      expectedSecurityDomainId: digest(localTestkit.securityDomainLabel),
      expectedManifestDigest: digest(localTestkit.manifestLabel),
      expectedExecutableDigest: digest(localTestkit.executableLabel),
      expectedQuorumKeyId: localTestkit.quorumKeyId,
      expectedQuorumPublicKey: localTestkit.quorumPublicKey,
      expectedEphemeralPublicKey: localTestkit.ephemeralPublicKey,
      expectedOperations: localTestkit.operations as readonly OperationKind[],
      ...(transport === undefined ? {} : { transport }),
    }, signal)
  ), genesisHash);
}
