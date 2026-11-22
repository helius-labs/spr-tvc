import { initializePoseidon, NullifierKey, ViewingKey } from "@heliuslabs/spr";
import { randomSalt, type Bytes31 } from "@heliuslabs/spr/keypair";
import { generateKeyPairSigner } from "@solana/kit";

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
import { checkPlaintexts, decryptItem } from "./items.js";

const nowMs = () => BigInt(Date.now());

export async function probeNitroTarget(target: NitroTarget, trust: NitroTrust, requestSignal?: AbortSignal) {
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
  await checkDecryptionCanary({ ...nitroOperationBinding(connected), ...window, nowMs }, signal);
  signal.throwIfAborted();
  requireCurrentReleasePolicy(window, nowMs());
  return { ...connected, window };
}

/** Prove the wallet can open a synthetic note through the verified replica. */
export async function checkDecryptionCanary(runtime: ConnectedTvcRuntime, signal: AbortSignal): Promise<void> {
  const owner = await awaitWithSignal(generateKeyPairSigner(), signal);
  const { viewingPublicKey, nullifierPublicKey } = decodePublicKeys(
    await executeServiceCall(runtime, { type: "PublicKeys", address: owner.address }, signal),
  );
  await awaitWithSignal(initializePoseidon(), signal);
  const plaintext = crypto.getRandomValues(new Uint8Array(32));
  const salt = randomSalt();
  const sender = ViewingKey.generate();
  let item: DecryptItem;
  try {
    item = decryptItem({
      ciphertext: sender.encryptSlot(viewingPublicKey, plaintext, salt, 1),
      viewingPublicKey, txViewingPublicKey: sender.publicKey(), salt, slotIndex: 1, label: "transfer",
    });
  } finally {
    sender.destroy();
  }
  const items = [item];
  const result = await executeServiceCall(runtime, { type: "Decrypt", owner, items }, signal);
  const secret = requireHex(result.nullifier_secret, 31) as Bytes31;
  let nullifier: NullifierKey | undefined;
  try {
    checkPlaintexts(result.plaintexts, items);
    if (result.plaintexts[0] !== encodeLowerHex(plaintext)) {
      throw new DecryptionServiceError("ReleaseBindingMismatch", "canary plaintext");
    }
    nullifier = NullifierKey.fromSecret(secret);
    if (!bytesEqual(nullifier.publicKey(), nullifierPublicKey)) {
      throw new DecryptionServiceError("ReleaseBindingMismatch", "canary nullifier key");
    }
  } finally {
    nullifier?.destroy();
    secret.fill(0);
  }
}
