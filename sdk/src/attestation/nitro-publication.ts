import { fetchWithSignal, httpError, readBoundedText } from "../connection/http.js";
import { nitroTransport } from "./nitro-connection.js";
import { nitroPublication, verifyPublishedNitroPolicy, type NitroTrust } from "./nitro-policy.js";

async function readPolicyObject(url: URL, signal: AbortSignal, account: string) {
  const response = await fetchWithSignal(nitroTransport, url, {
    headers: { "x-amz-expected-bucket-owner": account },
  }, signal);
  if (!response.ok) throw httpError(response, "ReleasePolicyInvalid");
  return {
    text: await readBoundedText(response, 32_768n, signal),
    versionId: response.headers.get("x-amz-version-id"),
  };
}

export async function readNitroPolicy(url: URL, signal: AbortSignal, account: string): Promise<string> {
  return (await readPolicyObject(url, signal, account)).text;
}

export async function readPublishedNitroPolicy(trust: NitroTrust, signal: AbortSignal) {
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(5_000)]);
  const [primary, mirror] = trust.publications;
  const read = (publication: NitroTrust["publications"][number]) => {
    const { url, account } = nitroPublication(trust, publication);
    return readPolicyObject(url, deadline, account);
  };
  const [first, second] = await Promise.all([read(primary), read(mirror)]);
  return {
    ...verifyPublishedNitroPolicy([first.text, second.text], trust, BigInt(Date.now())),
    text: first.text,
    versionIds: [first.versionId, second.versionId] as const,
  };
}
