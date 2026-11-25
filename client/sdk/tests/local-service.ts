import { sha256 } from "@noble/hashes/sha256";

import { decryptionServiceFromSession, type DecryptionService } from "../src/client/decryption.js";
import type { DecryptionServiceTransport } from "../src/connection/http.js";
import { connectLocalUnattestedTvc } from "../src/connection/local-connection.js";
import { sessionFromConnector } from "../src/connection/session.js";
import { encodeLowerHex } from "../src/wire/hex.js";
import { requireNetwork } from "../src/wire/network.js";
import type { Network, OperationKind } from "../src/wire/types.js";
import localTestkit from "../../../tests/fixtures/local-testkit.json";

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
