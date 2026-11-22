import { connectNitroTarget, nitroOperationBinding } from "../attestation/nitro-connection.js";
import type { NitroTarget, NitroTrust } from "../attestation/nitro-policy.js";
import { requireCurrentReleasePolicy } from "../connection/operations.js";
import { decodePublicKeys, executeServiceCall } from "./exchange.js";

// The Ed25519 base point encoded as a Solana address. This probe needs no signer.
const PROBE_ADDRESS = "6x5SYnLroiN7WYq8NQYU9KHcH4YjpBbwpUfVu3EB7ieH";
const nowMs = () => BigInt(Date.now());

export async function probeNitroTarget(target: NitroTarget, trust: NitroTrust, requestSignal?: AbortSignal) {
  const timeout = AbortSignal.timeout(7_000);
  const signal = requestSignal ? AbortSignal.any([requestSignal, timeout]) : timeout;
  const connected = await connectNitroTarget(target, trust, signal);
  const window = {
    releasePolicyValidFromMs: connected.certificateValidFromMs,
    releasePolicyExpiresAtMs: connected.certificateValidThroughMs,
  };
  const result = await executeServiceCall({
    ...nitroOperationBinding(connected), ...window, nowMs,
  }, { type: "PublicKeys", address: PROBE_ADDRESS }, signal);
  decodePublicKeys(result);
  signal.throwIfAborted();
  requireCurrentReleasePolicy(window, nowMs());
  return connected;
}
