import { fetchWithSignal, httpError, readBoundedText } from "../connection/http.js";
import { nitroTransport } from "./nitro-connection.js";
import { nitroPublication, verifyPublishedNitroPolicy, type NitroTrust } from "./nitro-policy.js";

export async function readNitroPolicy(url: URL, signal: AbortSignal, account: string): Promise<string> {
  const response = await fetchWithSignal(nitroTransport, url, {
    headers: { "x-amz-expected-bucket-owner": account },
  }, signal);
  if (!response.ok) throw httpError(response, "ReleasePolicyInvalid");
  return readBoundedText(response, 32_768n, signal);
}

export async function readPublishedNitroPolicy(trust: NitroTrust, signal: AbortSignal) {
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(5_000)]);
  const [first, second] = trust.publications;
  const read = (publication: NitroTrust["publications"][number]) => {
    const { url, account } = nitroPublication(trust, publication);
    return readNitroPolicy(url, deadline, account);
  };
  const texts = await Promise.all([read(first), read(second)]);
  return verifyPublishedNitroPolicy(texts, trust, BigInt(Date.now()));
}
