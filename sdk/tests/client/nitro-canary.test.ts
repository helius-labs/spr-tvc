import { expect, it } from "vitest";

import localTestkit from "../../../tests/fixtures/local-testkit.json";
import { createDecryptionCanary } from "../../src/client/nitro-probe.js";
import { fetchLiveServiceInfo } from "../../src/connection/connect.js";
import { createDefaultTransport } from "../../src/connection/http.js";

const localEndpoint = process.env["DECRYPTION_SERVICE_LOCAL_ENDPOINT"];

it.skipIf(!localEndpoint)("opens the operator canary against the Rust service", async () => {
  const endpoint = new URL(localEndpoint!);
  const signal = AbortSignal.timeout(7_000);
  const nowMs = () => BigInt(Date.now());
  const info = await fetchLiveServiceInfo(endpoint, signal);
  await createDecryptionCanary().check({
    backend: { endpoint },
    info,
    transport: createDefaultTransport(),
    nowMs,
    releasePolicyValidFromMs: 0n,
    releasePolicyExpiresAtMs: nowMs() + 7_000n,
    trustVerifier: {
      async verifyOperationAppProof(proof) {
        expect(proof.publicKey).toBe(localTestkit.ephemeralPublicKey);
      },
    },
  }, signal);
});
