import { fetchWithSignal, httpError, readBoundedText } from "../connection/http.js";
import { awaitWithSignal } from "../connection/request.js";
import { nitroTransport } from "./nitro-connection.js";
import { DecryptionServiceError } from "../protocol/error.js";
import {
  nitroPublication, requireCurrentNitroPolicy, revision, verifyNitroPolicyPair, verifySignedPolicy,
  type NitroPolicyUpdate, type NitroTrust,
} from "./nitro-policy.js";

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
  const read = async (publication: NitroTrust["publications"][number]) => {
    const { url, account } = nitroPublication(trust, publication);
    const head = await readPolicyObject(url, deadline, account);
    return { ...head, verified: verifySignedPolicy(head.text, trust) };
  };
  function verify(first: Awaited<ReturnType<typeof read>>, second: Awaited<ReturnType<typeof read>>) {
    return {
      ...verifyNitroPolicyPair(first.verified, second.verified, trust, BigInt(Date.now())),
      sameEnvelope: first.text === second.text,
      text: first.text,
      versionIds: [first.versionId, second.versionId] as const,
    };
  }
  const reads = [read(primary), read(mirror)] as const;
  if (!accept) return verify(...await Promise.all(reads));
  const stops = reads.map(read => read.then(async ({ verified }) => {
    if (!verified.checkpoint.revoked) return;
    try {
      requireCurrentNitroPolicy(verified, trust, BigInt(Date.now()));
    } catch (error) {
      if (!(error instanceof DecryptionServiceError)) throw error;
      return;
    }
    return await accept([revision(verified)]) ? "accepted" : "rejected";
  }, () => undefined));
  const [heads, revocations] = await awaitWithSignal(
    Promise.all([Promise.allSettled(reads), Promise.all(stops)]), signal,
  );
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
  if (revocations.includes("accepted")) throw new DecryptionServiceError("ReleasePolicyRevoked");
  if (published || revocations.includes("rejected")) {
    throw new DecryptionServiceError("ReleasePolicyInvalid", "policy rollback or checkpoint unavailable");
  }
  throw error;
}
