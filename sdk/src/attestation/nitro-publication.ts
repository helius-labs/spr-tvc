import { fetchWithSignal, httpError, readBoundedText } from "../connection/http.js";
import { nitroTransport } from "./nitro-connection.js";
import { DecryptionServiceError } from "../protocol/error.js";
import { nitroPublication, revision, verifyNitroPolicy, verifyPublishedNitroPolicy, type NitroPolicyRevision, type NitroPolicyUpdate, type NitroTrust } from "./nitro-policy.js";

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

export async function readPublishedNitroPolicy(
  trust: NitroTrust, signal?: AbortSignal, accept?: (update: NitroPolicyUpdate) => Promise<boolean>,
) {
  const timeout = AbortSignal.timeout(5_000);
  const deadline = signal ? AbortSignal.any([signal, timeout]) : timeout;
  const [primary, mirror] = trust.publications;
  const read = (publication: NitroTrust["publications"][number]) => {
    const { url, account } = nitroPublication(trust, publication);
    return readPolicyObject(url, deadline, account);
  };
  function verify(first: Awaited<ReturnType<typeof read>>, second: Awaited<ReturnType<typeof read>>) {
    return {
      ...verifyPublishedNitroPolicy([first.text, second.text], trust, BigInt(Date.now())),
      text: first.text,
      versionIds: [first.versionId, second.versionId] as const,
    };
  }
  const reads = [read(primary), read(mirror)] as const;
  if (!accept) return verify(...await Promise.all(reads));
  const heads = await Promise.allSettled(reads);
  let published: ReturnType<typeof verify> | undefined;
  let error: unknown;
  try {
    const [first, second] = heads;
    if (first.status === "rejected") throw first.reason;
    if (second.status === "rejected") throw second.reason;
    published = verify(first.value, second.value);
  } catch (failure) {
    error = failure;
  }
  if (published && await accept(published.update)) return published;
  signal?.throwIfAborted();
  const now = BigInt(Date.now());
  const revocations: NitroPolicyRevision[] = [];
  for (const head of heads) {
    if (head.status !== "fulfilled") continue;
    try {
      const verified = verifyNitroPolicy(head.value.text, trust, now);
      if (verified.checkpoint.revoked) revocations.push(revision(verified));
    } catch (invalid) {
      if (!(invalid instanceof DecryptionServiceError)) throw invalid;
    }
  }
  revocations.sort((first, second) => Number(BigInt(second.checkpoint.sequence) - BigInt(first.checkpoint.sequence)));
  for (const revoked of revocations) {
    if (await accept([revoked])) throw new DecryptionServiceError("ReleasePolicyRevoked");
  }
  if (published || revocations.length) {
    throw new DecryptionServiceError("ReleasePolicyInvalid", "policy rollback or checkpoint unavailable");
  }
  throw error;
}
