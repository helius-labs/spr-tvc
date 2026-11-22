import { awaitWithSignal } from "./request.js";
import { verifyP256Message } from "../crypto/p256.js";
import { parseQosP256Public, qosEncrypt } from "../crypto/qos.js";
import {
  API_VERSION,
  EXPECTED_TURNKEY_TRUST_ROOT_ID,
  QOS_P256_PUBLIC_LEN,
  TVC_APP_PROOF_KEYS,
  TVC_APP_PROOF_SCHEME,
  TVC_QOS_PING_PROOF_TYPE,
} from "../protocol/constants.js";
import { DecryptionServiceError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import { assertExactObjectKeys, parseStrictJson } from "../protocol/json.js";
import type { ReleaseTrust } from "../protocol/releases.js";
import { SERVICE_INFO_KEYS, type Network, type ServiceInfo } from "../protocol/types.js";
import { createDefaultTransport, type DecryptionServiceTransport } from "./http.js";
import { verifyBootProof, type QosIdentityPcrs } from "../attestation/boot-proof.js";
import type {
  TurnkeyAppProofWire,
  TurnkeyBootProofWire,
} from "../attestation/turnkey.js";
import { bindDiscoveryToPolicy, verifySignedReleasePolicy } from "../attestation/release-policy.js";
import { fetchDiscovery, fetchPing, fetchSession, lookupBootProof, type EnclaveBackend } from "./backend.js";
import { requireCurrentReleasePolicy } from "./operations.js";

const PING_RESPONSE_KEYS = ["version", "tvc_app_proof"] as const;

type QosPingResponse = {
  version: number;
  tvc_app_proof: {
    scheme: string;
    public_key: string;
    proof_payload: string;
    signature: string;
  };
};

export type DecryptionServiceConnectionConfig = {
  /** The network the enclave serves; the release policy must name it. */
  network: Network;
  /** Where the client reaches the enclave. */
  backend: EnclaveBackend;
  /** The release the enclave is verified against. */
  release: ReleaseTrust;
  /**
   * Verifier clock. A function, not an instant: a fixed value would freeze
   * request timestamps and certificate-chain validation for the client's
   * whole life.
   */
  nowMs?: () => bigint;
  transport?: DecryptionServiceTransport;
};

/** What one verification established: the release's discovery, bound to the policy, and how to check each answer. */
export type ConnectedTvcRuntime = {
  readonly backend: EnclaveBackend;
  readonly info: ServiceInfo;
  readonly transport: DecryptionServiceTransport;
  readonly responseTimeoutMs?: number;
  readonly recoveryOnly?: boolean;
  readonly releasePolicyValidFromMs: bigint;
  readonly releasePolicyExpiresAtMs: bigint;
  readonly policyFreshnessRemainingMs?: () => number;
  readonly requireCurrentCheckpoint?: (signal?: AbortSignal) => Promise<void>;
  readonly requirePublishedPolicy?: (signal?: AbortSignal, forPayment?: boolean) => Promise<void>;
  readonly nowMs: () => bigint;
  readonly trustVerifier: { verifyOperationAppProof(proof: TurnkeyAppProofWire, signal?: AbortSignal): Promise<void> };
};

export function parseServiceInfo(text: string): ServiceInfo {
  return parseStrictJson<ServiceInfo>(text, SERVICE_INFO_KEYS);
}

export async function fetchLiveServiceInfo(
  endpoint: URL,
  signal?: AbortSignal,
  transport = createDefaultTransport(),
): Promise<ServiceInfo> {
  return parseServiceInfo(await fetchDiscovery(endpoint, transport, signal));
}

function requireQosPublicKey(value: string): Uint8Array {
  const bytes = decodeLowerHex(value);
  if (bytes.length !== QOS_P256_PUBLIC_LEN) throw new DecryptionServiceError("InvalidPublicKey");
  return bytes;
}

/** A random challenge encrypted to the quorum key, and the payload the enclave must sign. */
export type QosPingChallenge = { readonly body: string; readonly payload: string };

export function qosPingChallenge(quorumPublicKey: string): QosPingChallenge {
  const quorumPublic = parseQosP256Public(requireQosPublicKey(quorumPublicKey));
  const payload = canonicalizeJsonValue({
    type: TVC_QOS_PING_PROOF_TYPE,
    version: API_VERSION,
    challenge: encodeLowerHex(crypto.getRandomValues(new Uint8Array(32))),
  });
  const body = canonicalizeJsonValue({
    version: API_VERSION,
    encrypted_challenge: encodeLowerHex(
      qosEncrypt(quorumPublic.encryption, new TextEncoder().encode(payload)),
    ),
  });
  return { body, payload };
}

export function verifyQosPingAnswer(text: string, challenge: QosPingChallenge): TurnkeyAppProofWire {
  const parsed = parseStrictJson<QosPingResponse>(text, PING_RESPONSE_KEYS);
  if (parsed.version !== API_VERSION) throw new DecryptionServiceError("UnsupportedVersion");
  assertExactObjectKeys(parsed.tvc_app_proof, TVC_APP_PROOF_KEYS, "TurnkeyEvidenceInvalid");
  const proof = parsed.tvc_app_proof;
  if (proof.scheme !== TVC_APP_PROOF_SCHEME || proof.proof_payload !== challenge.payload) {
    throw new DecryptionServiceError("TurnkeyEvidenceInvalid");
  }
  // The signature proves possession. The Boot Proof authenticates this key.
  verifyP256Message(
    parseQosP256Public(requireQosPublicKey(proof.public_key)).signing,
    new TextEncoder().encode(proof.proof_payload),
    decodeLowerHex(proof.signature),
  );
  return {
    scheme: TVC_APP_PROOF_SCHEME,
    publicKey: proof.public_key,
    proofPayload: proof.proof_payload,
    signature: proof.signature,
  };
}

/** What a release tool checks of a live replica before it signs a release policy for it. */
export type ApprovedDeployment = {
  readonly manifestDigest: string;
  readonly executableDigest: string;
  readonly quorumPublicKey: string;
};

export type VerifyLiveReplicaInput = {
  /** The enclave's public ingress. */
  readonly endpoint: URL;
  /** Discovery from the data plane. */
  readonly info: ServiceInfo;
  /** Identity derived from the authenticated deployment manifest. */
  readonly approved: ApprovedDeployment;
  /** The PCR0-3 pinned for the QOS version, never read from the enclave. */
  readonly qosIdentityPcrs: QosIdentityPcrs;
  /** The trust root the release names; only the one this package pins verifies. */
  readonly turnkeyTrustRootId: string;
  /** Turnkey's Boot Proof for the replica whose ephemeral public key is given. */
  readonly bootProof: (ephemeralPublicKey: string, signal?: AbortSignal) => Promise<TurnkeyBootProofWire>;
  readonly transport?: DecryptionServiceTransport;
  readonly nowMs?: bigint;
  readonly signal?: AbortSignal;
};

export async function verifyLiveReplica(input: VerifyLiveReplicaInput): Promise<void> {
  const { signal } = input;
  signal?.throwIfAborted();
  if (input.turnkeyTrustRootId !== EXPECTED_TURNKEY_TRUST_ROOT_ID) {
    throw new DecryptionServiceError("ReleasePolicyInvalid", `this client pins the trust root ${EXPECTED_TURNKEY_TRUST_ROOT_ID}`);
  }
  const info = parseServiceInfo(JSON.stringify(input.info));
  if (info.version !== API_VERSION ||
      info.manifest_digest !== input.approved.manifestDigest ||
      info.executable_digest !== input.approved.executableDigest ||
      info.quorum_public_key !== input.approved.quorumPublicKey) {
    throw new DecryptionServiceError("ReleaseBindingMismatch");
  }
  const transport = input.transport ?? createDefaultTransport();
  const challenge = qosPingChallenge(input.approved.quorumPublicKey);
  const appProof = verifyQosPingAnswer(
    await fetchPing(input.endpoint, challenge.body, transport, signal),
    challenge,
  );
  const bootProof = await awaitWithSignal(input.bootProof(appProof.publicKey, signal), signal);
  await awaitWithSignal(verifyBootProof({
    ephemeralPublicKey: appProof.publicKey,
    bootProof,
    allowedManifestSha256: [input.approved.manifestDigest],
    expectedPcrs: input.qosIdentityPcrs,
    nowMs: input.nowMs ?? BigInt(Date.now()),
  }), signal);
}

export async function connectAndVerifyTvc(
  config: DecryptionServiceConnectionConfig,
  signal?: AbortSignal,
): Promise<ConnectedTvcRuntime> {
  signal?.throwIfAborted();
  const nowMs = config.nowMs ?? (() => BigInt(Date.now()));
  const { backend, network, release } = config;
  const { releasePolicy, qosIdentityPcrs } = release;
  verifySignedReleasePolicy(releasePolicy, release.releaseAuthorities, network, nowMs());
  const transport = config.transport ?? createDefaultTransport();
  const window = {
    releasePolicyValidFromMs: BigInt(releasePolicy.policy.validFromMs),
    releasePolicyExpiresAtMs: BigInt(releasePolicy.policy.expiresAtMs),
  };

  const verifyReplica = async (
    appProof: TurnkeyAppProofWire,
    verifySignal?: AbortSignal,
  ) => {
    verifySignal?.throwIfAborted();
    requireCurrentReleasePolicy(window, nowMs());
    const bootProof = await lookupBootProof(backend, appProof, verifySignal);
    const verificationNow = nowMs();
    requireCurrentReleasePolicy(window, verificationNow);
    await awaitWithSignal(verifyBootProof({
      ephemeralPublicKey: appProof.publicKey,
      bootProof,
      allowedManifestSha256: releasePolicy.policy.acceptedManifestDigests,
      expectedPcrs: qosIdentityPcrs,
      nowMs: verificationNow,
    }), verifySignal);
  };

  const challenge = qosPingChallenge(releasePolicy.policy.quorumPublicKey);
  const session = await fetchSession(backend, challenge.body, transport, signal);
  const info = parseServiceInfo(session.infoText);
  bindDiscoveryToPolicy(info, releasePolicy);
  const appProof = verifyQosPingAnswer(session.pingText, challenge);
  await verifyReplica(appProof, signal);
  requireCurrentReleasePolicy(window, nowMs());

  return {
    backend,
    info,
    transport,
    ...window,
    nowMs,
    trustVerifier: Object.freeze({ verifyOperationAppProof: verifyReplica }),
  };
}
