import { sha256 } from "@noble/hashes/sha256";

import { connectLocalUnattestedTvc } from "./client/local-connection.js";
import { sessionFromConnector } from "./client/session.js";
import type { DecryptionServiceTransport } from "./client/transport.js";
import { decryptionServiceFromSession, type DecryptionService } from "./decryption-service/client.js";
import { encodeLowerHex } from "./protocol/hex.js";
import { requireNetwork } from "./protocol/network.js";
import type { Network, OperationKind } from "./protocol/types.js";
import localTestkit from "./local-testkit.json";

export { verifyLiveReplica, type VerifyLiveReplicaInput } from "./client/connection.js";

const encoder = new TextEncoder();
const digest = (label: string) => encodeLowerHex(sha256(encoder.encode(label)));

export function createLocalDecryptionService(config: {
  readonly network: Network;
  readonly endpoint: URL;
  readonly transport?: DecryptionServiceTransport;
}): DecryptionService {
  if (localTestkit.version !== 1) throw new Error("unsupported local testkit fixture");
  return decryptionServiceFromSession(sessionFromConnector((signal) =>
    connectLocalUnattestedTvc({
      network: requireNetwork(config.network),
      backend: { endpoint: config.endpoint },
      expectedReleaseId: localTestkit.releaseId,
      expectedSecurityDomainId: digest(localTestkit.securityDomainLabel),
      expectedManifestDigest: digest(localTestkit.manifestLabel),
      expectedExecutableDigest: digest(localTestkit.executableLabel),
      expectedQuorumKeyId: localTestkit.quorumKeyId,
      expectedQuorumPublicKey: localTestkit.quorumPublicKey,
      expectedEphemeralPublicKey: localTestkit.ephemeralPublicKey,
      expectedOperations: localTestkit.operations as readonly OperationKind[],
      ...(config.transport === undefined ? {} : { transport: config.transport }),
    }, signal)
  ));
}
