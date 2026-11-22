import { initializePoseidon, NullifierKey, ViewingKey } from "@heliuslabs/spr";
import { randomSalt, type Bytes16, type Bytes31, type Bytes32 } from "@heliuslabs/spr/keypair";
import { sha256 } from "@noble/hashes/sha256";
import { concatBytes } from "@noble/hashes/utils";
import { createKeyPairSignerFromPrivateKeyBytes, generateKeyPairSigner } from "@solana/kit";

import { connectNitroTarget, nitroOperationBinding } from "../attestation/nitro-connection.js";
import type { NitroTarget, NitroTrust } from "../attestation/nitro-policy.js";
import type { ConnectedTvcRuntime } from "../connection/connect.js";
import { requireCurrentReleasePolicy } from "../connection/operations.js";
import { awaitWithSignal } from "../connection/request.js";
import { MAX_CLOCK_SKEW_MS } from "../protocol/constants.js";
import { DecryptionServiceError } from "../protocol/error.js";
import { bytesEqual, encodeLowerHex, requireHex } from "../protocol/hex.js";
import type { DecryptItem } from "../protocol/types.js";
import { decodePublicKeys, executeServiceCall } from "./exchange.js";
import { decryptItem } from "./items.js";

const nowMs = () => BigInt(Date.now());
const encoder = new TextEncoder();
const CANARY_DOMAIN = encoder.encode("SPR/native-nitro/canary/v1");
type CanaryAnchor = Pick<NitroTrust, "securityDomainId" | "noteSeedCommitment"> & {
  readonly canaryDigest: string;
};

export async function probeNitroTarget(
  target: NitroTarget,
  trust: NitroTrust,
  { signal: requestSignal, canary = createDecryptionCanary() }: {
    signal?: AbortSignal;
    canary?: DecryptionCanary;
  } = {},
) {
  const expiresAt = nowMs() + MAX_CLOCK_SKEW_MS - 1n;
  const deadline = performance.now() + Number(MAX_CLOCK_SKEW_MS);
  const timeout = AbortSignal.timeout(7_000);
  const signal = requestSignal ? AbortSignal.any([requestSignal, timeout]) : timeout;
  const connected = await connectNitroTarget(target, trust, signal);
  const window = {
    releasePolicyValidFromMs: connected.certificateValidFromMs,
    releasePolicyExpiresAtMs: [expiresAt, connected.attestedAtMs + MAX_CLOCK_SKEW_MS, connected.certificateValidThroughMs]
      .reduce((earliest, limit) => earliest < limit ? earliest : limit),
    policyFreshnessRemainingMs: () => deadline - performance.now(),
  };
  await canary.check({ ...nitroOperationBinding(connected), ...window, nowMs }, signal);
  signal.throwIfAborted();
  requireCurrentReleasePolicy(window, nowMs());
  return { ...connected, window };
}

function makeCanaryNote(
  keys: ReturnType<typeof decodePublicKeys>,
  reference?: (label: string) => Uint8Array,
) {
  const { viewingPublicKey } = keys;
  const transfer = reference?.("canary-transfer") ?? crypto.getRandomValues(new Uint8Array(32));
  const salt = reference ? new Uint8Array(16) as Bytes16 : randomSalt();
  const sender = reference ? ViewingKey.fromBytes(reference("canary-sender") as Bytes32) : ViewingKey.generate();
  const items: DecryptItem[] = [];
  const plaintexts = [encodeLowerHex(transfer)];
  let digest: Uint8Array | undefined;
  try {
    const transferCiphertext = sender.encryptSlot(viewingPublicKey, transfer, salt, 1);
    const txViewingPublicKey = sender.publicKey();
    items.push(decryptItem({
      ciphertext: transferCiphertext, viewingPublicKey, txViewingPublicKey, salt, slotIndex: 1, label: "transfer",
    }));
    if (reference) {
      const ring = reference("canary-ring-deposit");
      const ringCiphertext = sender.encryptRingDeposit(viewingPublicKey, ring, salt);
      if (transferCiphertext.length !== 32 || ringCiphertext.length !== 32) {
        throw new CanaryMismatch("custody canary ciphertext length");
      }
      items.push(decryptItem({
        ciphertext: ringCiphertext, viewingPublicKey, txViewingPublicKey, salt, slotIndex: 0, label: "ringDeposit",
      }));
      plaintexts.push(encodeLowerHex(ring));
      digest = sha256(concatBytes(CANARY_DOMAIN, viewingPublicKey.toBytes(), keys.nullifierPublicKey,
        txViewingPublicKey.toBytes(), salt, Uint8Array.of(0, 0, 0, 1), transfer, ring, transferCiphertext, ringCiphertext));
    }
  } finally {
    sender.destroy();
  }
  return { keys, plaintexts, items, digest };
}

export type DecryptionCanary = ReturnType<typeof createDecryptionCanary>;

export class CanaryMismatch extends DecryptionServiceError {
  constructor(detail = "canary recipient keys differ between replicas") {
    super("ReleaseBindingMismatch", detail);
  }
}

/** A missing replica supplies no comparison. A verified disagreement blocks the group. */
export function requireCanaryAgreement(results: readonly PromiseSettledResult<unknown>[]): void {
  for (const result of results) {
    if (result.status === "rejected" && result.reason instanceof CanaryMismatch) throw result.reason;
  }
}

/** Check the same owner and encrypted note across all replicas in a qualification. */
export function createDecryptionCanary(anchor?: CanaryAnchor) {
  let signer: ReturnType<typeof generateKeyPairSigner> | undefined;
  let referenceKeys: ReturnType<typeof decodePublicKeys> | undefined;
  let note: ReturnType<typeof makeCanaryNote> | undefined;
  const digest = anchor && requireHex(anchor.canaryDigest, 32);
  const scope = anchor && concatBytes(requireHex(anchor.securityDomainId, 32), requireHex(anchor.noteSeedCommitment, 32));
  const reference = scope && ((label: string) => sha256(concatBytes(encoder.encode(`SPR/native-nitro/${label}/v1`), scope)));

  return {
    async check(runtime: ConnectedTvcRuntime, signal: AbortSignal): Promise<void> {
      signer ??= reference
        ? createKeyPairSignerFromPrivateKeyBytes(reference("canary-owner"))
        : generateKeyPairSigner();
      const owner = await awaitWithSignal(signer, signal);
      const result = await executeServiceCall(runtime, { type: "PublicKeys", address: owner.address }, signal);
      let keys: ReturnType<typeof decodePublicKeys>;
      try {
        keys = decodePublicKeys(result);
      } catch {
        throw new CanaryMismatch("invalid canary recipient keys");
      }
      signal.throwIfAborted();
      const expected = referenceKeys ??= keys;
      if (!bytesEqual(keys.viewingPublicKey.toBytes(), expected.viewingPublicKey.toBytes()) ||
          !bytesEqual(keys.nullifierPublicKey, expected.nullifierPublicKey)) {
        throw new CanaryMismatch();
      }
      await awaitWithSignal(initializePoseidon(), signal);
      signal.throwIfAborted();
      note ??= makeCanaryNote(expected, reference);
      if (digest && (!note.digest || !bytesEqual(digest, note.digest))) {
        throw new CanaryMismatch("canary keys or ciphertext differ from the custody receipt");
      }
      await openCanaryNote(runtime, owner, note, signal);
    },
  };
}

async function openCanaryNote(
  runtime: ConnectedTvcRuntime,
  owner: Awaited<ReturnType<typeof generateKeyPairSigner>>,
  { items, plaintexts, keys }: ReturnType<typeof makeCanaryNote>,
  signal: AbortSignal,
): Promise<void> {
  const result = await executeServiceCall(runtime, { type: "Decrypt", owner, items }, signal);
  let secret: Bytes31 | undefined;
  let nullifier: NullifierKey | undefined;
  try {
    if (!Array.isArray(result.plaintexts) || result.plaintexts.length !== plaintexts.length ||
        plaintexts.some((plaintext, index) => result.plaintexts[index] !== plaintext)) {
      throw new CanaryMismatch("canary plaintext");
    }
    try {
      secret = requireHex(result.nullifier_secret, 31) as Bytes31;
      nullifier = NullifierKey.fromSecret(secret);
    } catch {
      throw new CanaryMismatch("invalid canary nullifier secret");
    }
    if (!bytesEqual(nullifier.publicKey(), keys.nullifierPublicKey)) {
      throw new CanaryMismatch("canary nullifier key");
    }
  } finally {
    nullifier?.destroy();
    secret?.fill(0);
  }
}
