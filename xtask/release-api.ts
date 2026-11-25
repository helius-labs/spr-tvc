import { readFileSync } from "node:fs";

import type { VerifyLiveReplicaInput } from "../sdk/dist/release.js";

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`missing ${name}`);
  return value;
}

const [operation, value] = process.argv.slice(2);
if (operation === "info" && value) {
  const { fetchLiveServiceInfo } = await import("../sdk/dist/release.js");
  const info = await fetchLiveServiceInfo(new URL(value), AbortSignal.timeout(10_000));
  console.log(JSON.stringify(info));
} else {
  const { Turnkey } = await import("@turnkey/sdk-server");
  const organizationId = requiredEnv("TVC_ORG_ID");
  const turnkey = new Turnkey({
    apiBaseUrl: requiredEnv("SPR_TVC_API_BASE_URL"),
    apiPublicKey: requiredEnv("TVC_API_KEY_PUBLIC"),
    apiPrivateKey: requiredEnv("TVC_API_KEY_PRIVATE"),
    defaultOrganizationId: organizationId,
  }).apiClient();

  if (operation === "deployment" && value) {
    const { tvcDeployment } = await turnkey.getTvcDeployment({ organizationId, deploymentId: value });
    if (!tvcDeployment) throw new Error("Turnkey returned no deployment");
    console.log(JSON.stringify(tvcDeployment));
  } else if (operation === "verify") {
    const input = JSON.parse(readFileSync(0, "utf8")) as
      Omit<VerifyLiveReplicaInput, "endpoint" | "bootProof" | "signal"> & { endpoint: string };
    const { verifyLiveReplica } = await import("../sdk/dist/release.js");
    await verifyLiveReplica({
      ...input,
      endpoint: new URL(input.endpoint),
      signal: AbortSignal.timeout(30_000),
      async bootProof(ephemeralKey) {
        const { bootProof } = await turnkey.getBootProof({ organizationId, ephemeralKey });
        if (!bootProof) throw new Error("Turnkey returned no Boot Proof");
        return bootProof;
      },
    });
  } else {
    throw new Error("expected info, deployment, or verify");
  }
}
