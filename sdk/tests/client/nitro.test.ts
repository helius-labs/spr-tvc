import { p256 } from "@noble/curves/p256";
import { ed25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { concatBytes } from "@noble/hashes/utils";
import { address, getAddressEncoder, signatureBytes, type MessagePartialSigner } from "@solana/kit";
import { NullifierKey, ViewingKey, initializePoseidon, type ProofService } from "@heliuslabs/spr";
import { X25519PublicKey, type Bytes16, type Bytes31, type Bytes32 } from "@heliuslabs/spr/keypair";
import { BN254_MODULUS_DEC } from "@heliuslabs/spr/transaction";
import { IDBFactory } from "fake-indexeddb";
import { afterEach, describe, expect, it, vi } from "vitest";
import { verifyNativeNitroEvidence } from "../../src/attestation/boot-proof.js";
import { indexedDbNitroPolicyStore } from "../../src/attestation/nitro-checkpoint.js";
import { nitroCustodySigningDigest, nitroPolicySigningDigest, type NitroPolicy, type NitroPolicyCheckpoint, type NitroPolicyUpdate, type NitroTrust } from "../../src/attestation/nitro-policy.js";
import { createDecryptionCanary, probeNitroTarget, requireCanaryAgreement } from "../../src/client/nitro-probe.js";
import { createNitroDecryptionService } from "../../src/client/nitro.js";
import { signP256Message, signP256Prehash } from "../../src/crypto/p256.js";
import { qosDecrypt, qosEncrypt } from "../../src/crypto/qos.js";
import { TVC_APP_PROOF_SCHEME } from "../../src/protocol/constants.js";
import type { DecryptItem } from "../../src/protocol/types.js";
import { decryptMessage, SERVICE_PROOF_TYPE, serviceRequestDigest, type ServiceRequest, type ServiceResult } from "../../src/protocol/decryption.js";
import { resultDigest } from "../../src/protocol/digest.js";
import { encodeLowerHex, requireHex } from "../../src/protocol/hex.js";
import { canonicalizeJsonValue } from "../../src/protocol/jcs.js";

vi.mock("../../src/attestation/boot-proof.js", () => ({ verifyNativeNitroEvidence: vi.fn() }));

const secrets = [1, 2].map(value => new Uint8Array(32).fill(value));
const custodySecrets = [5, 6, 7].map(value => new Uint8Array(32).fill(value));
const trust: NitroTrust = {
  network: "mainnet", securityDomainId: "55".repeat(32), noteSeedCommitment: "66".repeat(32),
  minimumSequence: "1", minimumPolicyDigest: "88".repeat(32), minimumCustodyEpoch: "1", threshold: 2,
  publications: [
    { bucket: "release-test", region: "eu-north-1", account: "000000000001" },
    { bucket: "release-peer", region: "eu-west-1", account: "000000000002" },
  ],
  keys: secrets.map(secret => encodeLowerHex(p256.getPublicKey(secret, false))),
  custodyKeys: custodySecrets.map(secret => encodeLowerHex(p256.getPublicKey(secret, false))),
};

function signedPolicy(overrides: Partial<NitroPolicy> = {}) {
  const now = Date.now();
  const policy: NitroPolicy = {
    network: trust.network, securityDomainId: trust.securityDomainId, noteSeedCommitment: trust.noteSeedCommitment,
    publications: trust.publications,
    version: 1, action: "activate", recoveryOnly: false, sequence: "2", minimumCustodyEpoch: "1",
    previousPolicyDigest: "88".repeat(32),
    validFromMs: String(now - 1000), expiresAtMs: String(now + 100_000),
    targets: [{
      endpoint: "https://replica.example.com/",
      releaseId: "nitro-2",
      custodyEpoch: "1", custodyDigest: "99".repeat(32),
      executableSha256: "77".repeat(32),
      pcrs: { 0: "11".repeat(48), 1: "22".repeat(48), 2: "33".repeat(48), 3: "44".repeat(48), 4: "56".repeat(48) },
    }],
    ...overrides,
  };
  return JSON.stringify({ policy, signatures: secrets.map((secret, index) => ({
    key: trust.keys[index],
    signature: encodeLowerHex(signP256Prehash(secret, nitroPolicySigningDigest(policy))),
  })), custodySignatures: custodySecrets.slice(0, 2).map((secret, index) => ({
    key: trust.custodyKeys[index], signature: encodeLowerHex(signP256Prehash(secret, nitroCustodySigningDigest(policy))),
  })) });
}

function policyHeads(fetch = vi.fn(), first = signedPolicy(), second = first) {
  return fetch.mockResolvedValueOnce(new Response(first)).mockResolvedValueOnce(new Response(second));
}

function publicPair(boot: readonly Uint8Array[]) {
  return boot.map(secret => encodeLowerHex(p256.getPublicKey(secret, false))).join("");
}

function attestedDiscovery(custodyDigest = "99".repeat(32), boot = secrets, certificateValidThroughMs = BigInt(Date.now()) + 120_000n) {
  const pair = publicPair(boot);
  const executable = "77".repeat(32);
  const identity = sha256(Uint8Array.from([
    ...new TextEncoder().encode("SPR/native-nitro/release/v1"),
    ...requireHex(executable, 32), ...requireHex(trust.noteSeedCommitment, 32), ...requireHex(custodyDigest, 32),
  ]));
  vi.mocked(verifyNativeNitroEvidence).mockResolvedValue({
    proofKey: pair, attestedAtMs: BigInt(Date.now()), certificateValidFromMs: BigInt(Date.now()) - 1_000n, certificateValidThroughMs,
  });
  return Response.json({ boot: { bootstrapSlots: [1, 3, 5], bootedAtMs: String(Date.now() - 10_000), info: {
    version: 1, network: trust.network, security_domain_id: trust.securityDomainId, release_id: "nitro-2",
    manifest_digest: encodeLowerHex(identity), executable_digest: executable, quorum_public_key: pair,
    quorum_key_id: encodeLowerHex(sha256(requireHex(pair, 130))), quorum_key_epoch: "1",
    supported_operations: ["ServicePublicKeys", "ServiceDecrypt"], proof_type: "spr.tvc.decryption_service.v1",
    max_encrypted_request_bytes: "262144", max_encrypted_response_bytes: "262144",
  } }, evidence: "aa" });
}

const signMessages = vi.fn<MessagePartialSigner["signMessages"]>();
const signer = { address: address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3"), signMessages };
const proofs = {} as ProofService;
const emptyStore = { async current() { return undefined; } };
const replacementBoot = [3, 4].map(value => new Uint8Array(32).fill(value));
const replacement = "https://replacement.example.com/";
const nullifierModulus = BigInt(BN254_MODULUS_DEC).toString(16);

function twoReplicas() {
  const { policy } = JSON.parse(signedPolicy()) as { policy: NitroPolicy };
  const first = policy.targets[0]!;
  return signedPolicy({ targets: [first, { ...first, endpoint: replacement }] });
}

function checkpointStore() {
  let current: NitroPolicyCheckpoint | undefined;
  return {
    async current() { return current; },
    async accept(update: NitroPolicyUpdate) { current = update[0].checkpoint; return true; },
  };
}

function openRequest(init: RequestInit, boot: readonly Uint8Array[]): ServiceRequest {
  const { ciphertext } = JSON.parse(String(init.body)) as { ciphertext: string };
  return JSON.parse(new TextDecoder().decode(qosDecrypt(boot[0]!, requireHex(ciphertext)))) as ServiceRequest;
}

function lookupReply(init: RequestInit, boot: readonly Uint8Array[], owner: string = signer.address,
  nullifierPublicKey = "01".repeat(32),
) {
  const request = openRequest(init, boot);
  expect(request.operation).toEqual({ type: "PublicKeys", address: owner });
  const viewing = ViewingKey.generate();
  try {
    return signedReply(request, boot, { type: "PublicKeys", viewing_public_key: encodeLowerHex(viewing.publicKey().toBytes()),
      nullifier_public_key: nullifierPublicKey });
  } finally { viewing.destroy(); }
}

function signedReply(request: ServiceRequest, boot: readonly Uint8Array[],
  result: Partial<ServiceResult> & Pick<ServiceResult, "type">,
) {
  const text = new TextEncoder();
  const reply = qosEncrypt(requireHex(request.client_response_public_key), text.encode(canonicalizeJsonValue(result)));
  const proof = canonicalizeJsonValue({
    type: SERVICE_PROOF_TYPE, version: 1, request_id: request.request_id,
    request_digest: encodeLowerHex(serviceRequestDigest(request)), result_digest: encodeLowerHex(resultDigest(reply)),
    operation: result.type === "PublicKeys" ? "ServicePublicKeys" : "ServiceDecrypt",
  });
  return Response.json({ version: 1, request_id: request.request_id, encrypted_result: encodeLowerHex(reply), tvc_app_proof: {
    scheme: TVC_APP_PROOF_SCHEME, public_key: publicPair(boot), proof_payload: proof,
    signature: encodeLowerHex(signP256Message(boot[1]!, text.encode(proof))),
  } });
}

function openCanaryItem(viewing: ViewingKey, item: DecryptItem) {
  const ciphertext = requireHex(item.ciphertext);
  const sender = X25519PublicKey.fromBytes(requireHex(item.ephemeral_viewing_public_key, 33));
  const salt = requireHex(item.salt, 16) as Bytes16;
  return item.label === "Transfer"
    ? viewing.decryptUtxo(ciphertext, sender, salt, Number(item.slot_index))
    : viewing.decryptRingDeposit(ciphertext, sender, salt);
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.mocked(verifyNativeNitroEvidence).mockReset();
  signMessages.mockClear();
});

describe("operator replica probe", () => {
  it("requires the operation route and a signed reply from the attested boot", async () => {
    const { policy } = JSON.parse(signedPolicy()) as { policy: NitroPolicy };
    const target = policy.targets[0]!;
    const fetch = vi.fn<(url: URL, init: RequestInit) => Promise<Response>>();
    vi.stubGlobal("fetch", fetch);
    fetch.mockResolvedValueOnce(attestedDiscovery()).mockResolvedValueOnce(new Response(null, { status: 503 }));
    await expect(probeNitroTarget(target, trust)).rejects.toThrow("HTTP 503");

    fetch.mockResolvedValueOnce(attestedDiscovery()).mockImplementationOnce(async (_url, init) =>
      signedReply(openRequest(init, secrets), replacementBoot, {
        type: "PublicKeys", viewing_public_key: "01".repeat(33), nullifier_public_key: "01".repeat(32),
      }));
    await expect(probeNitroTarget(target, trust)).rejects.toThrow("BootProofUnverified");

    for (const [viewing, nullifier] of [
      ["04" + "01".repeat(32), "01".repeat(31)],
      ["01".repeat(33), "01".repeat(32)],
      ["04" + "01".repeat(32), nullifierModulus],
    ] as const) {
      fetch.mockResolvedValueOnce(attestedDiscovery()).mockImplementationOnce(async (_url, init) =>
        signedReply(openRequest(init, secrets), secrets, {
          type: "PublicKeys", viewing_public_key: viewing, nullifier_public_key: nullifier,
        }));
      const probe = probeNitroTarget(target, trust);
      await expect(probe).rejects.toThrow("invalid canary recipient keys");
      const results = await Promise.allSettled([probe]);
      expect(() => requireCanaryAgreement(results)).toThrow("invalid canary recipient keys");
    }

    const paths = ["/v1/nitro/attestation", "/v1/operations"];
    expect(fetch.mock.calls.map(([url]) => url.pathname)).toEqual(Array.from({ length: 5 }, () => paths).flat());
  });

  it.each([
    ["valid", undefined],
    ["wrong plaintext", "canary plaintext"],
    ["wrong nullifier", "canary nullifier key"],
    ["different boot", "BootProofUnverified"],
    ["unavailable decrypt", "HTTP 503"],
  ])("qualifies only a signed canary that opens on the same boot (%s)", async (fault, error) => {
    await initializePoseidon();
    const { policy } = JSON.parse(signedPolicy()) as { policy: NitroPolicy };
    const viewing = ViewingKey.generate();
    const secret = new Uint8Array(31).fill(9) as Bytes31;
    const nullifier = NullifierKey.fromSecret(secret);
    let owner: string | undefined;
    const fetch = vi.fn(async (url: URL, init: RequestInit) => {
      if (url.pathname === "/v1/nitro/attestation") return attestedDiscovery();
      const request = openRequest(init, secrets);
      const operation = request.operation;
      if (operation.type === "PublicKeys") {
        owner = operation.address;
        return signedReply(request, secrets, {
          type: "PublicKeys", viewing_public_key: encodeLowerHex(viewing.publicKey().toBytes()),
          nullifier_public_key: encodeLowerHex(nullifier.publicKey()),
        });
      }
      expect(operation.signer).toBe(owner);
      expect(BigInt(operation.expires_at_ms)).toBeGreaterThan(BigInt(Date.now()));
      const ownerBytes = new Uint8Array(getAddressEncoder().encode(address(operation.signer)));
      expect(ed25519.verify(requireHex(operation.signature, 64),
        decryptMessage(ownerBytes, trust.network, serviceRequestDigest(request)), ownerBytes)).toBe(true);
      expect(operation.items).toHaveLength(1);
      const item = operation.items[0]!;
      expect(item.label).toBe("Transfer");
      const plaintext = openCanaryItem(viewing, item);
      if (fault === "unavailable decrypt") return new Response(null, { status: 503 });
      if (fault === "wrong plaintext") plaintext[0] = plaintext[0]! ^ 1;
      return signedReply(request, fault === "different boot" ? replacementBoot : secrets, {
        type: "Decrypt", plaintexts: [encodeLowerHex(plaintext)],
        nullifier_secret: fault === "wrong nullifier" ? "10".repeat(31) : encodeLowerHex(secret),
      });
    });
    vi.stubGlobal("fetch", fetch);
    try {
      const probe = probeNitroTarget(policy.targets[0]!, trust);
      if (error) await expect(probe).rejects.toThrow(error);
      else expect((await probe).bootstrapSlots).toEqual([1, 3, 5]);
      expect(fetch.mock.calls.map(([url]) => url.pathname)).toEqual([
        "/v1/nitro/attestation", "/v1/operations", "/v1/operations",
      ]);
    } finally {
      viewing.destroy();
      nullifier.destroy();
      secret.fill(0);
    }
  });

  it.each(["agree", "viewing key", "nullifier key", "offline"])(
    "checks one note across independently attested replicas when they %s", async outcome => {
      await initializePoseidon();
      const { policy } = JSON.parse(twoReplicas()) as { policy: NitroPolicy };
      const [first, second] = policy.targets;
      const viewing = ViewingKey.generate();
      const differentViewing = ViewingKey.generate();
      const secret = new Uint8Array(31).fill(9) as Bytes31;
      const otherSecret = new Uint8Array(31).fill(10) as Bytes31;
      const nullifier = NullifierKey.fromSecret(secret);
      const differentNullifier = NullifierKey.fromSecret(otherSecret);
      const owners: string[] = [];
      const requests: { items: readonly DecryptItem[]; id: string; responseKey: string }[] = [];
      const fetch = vi.fn(async (url: URL, init: RequestInit) => {
        const isSecond = url.origin === new URL(second!.endpoint).origin;
        const boot = isSecond ? replacementBoot : secrets;
        if (url.pathname === "/v1/nitro/attestation") {
          return isSecond && outcome === "offline" ? new Response(null, { status: 503 })
            : attestedDiscovery(undefined, boot);
        }
        const request = openRequest(init, boot);
        if (request.operation.type === "PublicKeys") {
          owners.push(request.operation.address);
          const view = isSecond && outcome === "viewing key" ? differentViewing : viewing;
          const nf = isSecond && outcome === "nullifier key" ? differentNullifier : nullifier;
          return signedReply(request, boot, {
            type: "PublicKeys", viewing_public_key: encodeLowerHex(view.publicKey().toBytes()),
            nullifier_public_key: encodeLowerHex(nf.publicKey()),
          });
        }
        requests.push({
          items: request.operation.items, id: request.request_id, responseKey: request.client_response_public_key,
        });
        expect(request.operation.signer).toBe(owners[0]);
        return signedReply(request, boot, {
          type: "Decrypt", nullifier_secret: encodeLowerHex(secret),
          plaintexts: request.operation.items.map(item => encodeLowerHex(openCanaryItem(viewing, item))),
        });
      });
      vi.stubGlobal("fetch", fetch);
      const canary = createDecryptionCanary();
      try {
        await probeNitroTarget(first!, trust, { canary });
        const replacementProbe = probeNitroTarget(second!, trust, { canary });
        const results = await Promise.allSettled([replacementProbe]);
        if (outcome === "offline") {
          await expect(replacementProbe).rejects.toThrow("BootProofUnverified");
          expect(() => requireCanaryAgreement(results)).not.toThrow();
          expect(requests).toHaveLength(1);
          return;
        }
        if (outcome === "agree") {
          await replacementProbe;
          expect(() => requireCanaryAgreement(results)).not.toThrow();
          expect(requests).toHaveLength(2);
          const [original, duplicate] = requests;
          expect(duplicate!.items).toEqual(original!.items);
          expect(duplicate!.id).not.toBe(original!.id);
          expect(duplicate!.responseKey).not.toBe(original!.responseKey);
        } else {
          await expect(replacementProbe).rejects.toThrow("canary recipient keys differ");
          expect(() => requireCanaryAgreement(results)).toThrow("canary recipient keys differ");
          expect(requests).toHaveLength(1);
        }
        expect(owners).toEqual([owners[0], owners[0]]);
      } finally {
        viewing.destroy();
        differentViewing.destroy();
        nullifier.destroy();
        differentNullifier.destroy();
        secret.fill(0);
        otherSecret.fill(0);
      }
    },
  );

  it.each([
    "match", "changed keys", "changed ciphertext", "wrong ring plaintext",
    "missing ring plaintext", "invalid nullifier secret", "missing result field", "unsigned reply",
  ])(
    "checks a cold replacement against both original ciphertexts (%s)", async fault => {
    await initializePoseidon();
    const { policy } = JSON.parse(signedPolicy()) as { policy: NitroPolicy };
    const owner = address("HipQetrvjSHETfCDtgUcdVaP4n3UdYcfhhqxCfscvz8C");
    const ownerBytes = new Uint8Array(getAddressEncoder().encode(owner));
    const viewing = ViewingKey.fromBytes(hkdf(sha256, new Uint8Array(32).fill(0x88), undefined,
      concatBytes(new TextEncoder().encode("TSPP/decryption-service/view_key/x25519/v1"), ownerBytes), 32) as Bytes32);
    const secret = requireHex("70ad8470a7e869d8996911862ea64081249839c0384eac02e59dcad1487763", 31) as Bytes31;
    const nullifier = NullifierKey.fromSecret(secret);
    // The changed ciphertext digest differs only by one byte of the ring-deposit ciphertext.
    const canary = createDecryptionCanary({ ...trust, canaryDigest: fault === "changed ciphertext"
      ? "3e51734de66d49ac117c8d132ba0fc299d02c46b40dfdbe9c8850d00d0b87a8c"
      : "1b94ae1a401fa7ad8325ee93fa4ca43f99ac844689a5e52a4a74a95c848aa960" });
    const fetch = vi.fn(async (url: URL, init: RequestInit) => {
      if (url.pathname === "/v1/nitro/attestation") return attestedDiscovery();
      const request = openRequest(init, secrets);
      const { operation } = request;
      if (operation.type === "PublicKeys") {
        expect(operation.address).toBe(owner);
        return signedReply(request, secrets, {
          type: "PublicKeys", viewing_public_key: encodeLowerHex(viewing.publicKey().toBytes()),
          nullifier_public_key: fault === "changed keys" ? "01".repeat(32) : encodeLowerHex(nullifier.publicKey()),
        });
      }
      expect(operation.signer).toBe(owner);
      expect(ed25519.verify(requireHex(operation.signature, 64),
        decryptMessage(ownerBytes, trust.network, serviceRequestDigest(request)), ownerBytes)).toBe(true);
      expect(operation.items.map(({ label, slot_index, ciphertext }) => [label, slot_index, ciphertext])).toEqual([
        ["Transfer", "1", "9a2f49ddfa219a7eb2c118af23e554e5f0ba4ad2947d6008694394970b3b97df"],
        ["RingDeposit", "0", "d3eba4cb46b23b92bda860554cf33c0e7f4f24839be4eec970228eb24acfcac4"],
      ]);
      const plaintexts = operation.items.map(item => encodeLowerHex(openCanaryItem(viewing, item)));
      if (fault === "wrong ring plaintext") plaintexts[1] = "00".repeat(32);
      if (fault === "missing ring plaintext") plaintexts.pop();
      if (fault === "unsigned reply") return Response.json({});
      return signedReply(request, secrets, {
        type: "Decrypt", nullifier_secret: fault === "invalid nullifier secret" ? "00" : encodeLowerHex(secret),
        ...(fault === "missing result field" ? {} : { plaintexts }),
      });
    });
    vi.stubGlobal("fetch", fetch);
    try {
      const probe = probeNitroTarget(policy.targets[0]!, trust, { canary });
      const differentDigest = fault === "changed keys" || fault === "changed ciphertext";
      if (differentDigest) await expect(probe).rejects.toThrow("canary keys or ciphertext differ from the custody receipt");
      else if (fault === "wrong ring plaintext" || fault === "missing ring plaintext") {
        await expect(probe).rejects.toThrow("canary plaintext");
      } else if (fault === "invalid nullifier secret") await expect(probe).rejects.toThrow("invalid canary nullifier secret");
      else if (fault === "missing result field" || fault === "unsigned reply") {
        await expect(probe).rejects.toThrow("InvalidCanonicalJson");
      }
      else await expect(probe).resolves.toBeDefined();
      const results = await Promise.allSettled([probe]);
      if (fault === "match" || fault === "unsigned reply") expect(() => requireCanaryAgreement(results)).not.toThrow();
      else expect(() => requireCanaryAgreement(results)).toThrow();
      expect(fetch).toHaveBeenCalledTimes(differentDigest ? 2 : 3);
    } finally {
      viewing.destroy();
      nullifier.destroy();
      secret.fill(0);
    }
  });

  it.each(["PublicKeys", "Decrypt"])("honors the operator deadline during %s", async stalled => {
    const { policy } = JSON.parse(signedPolicy()) as { policy: NitroPolicy };
    const controller = new AbortController();
    const fetch = vi.fn()
      .mockResolvedValueOnce(attestedDiscovery())
      .mockImplementation((_url, init: RequestInit) => {
        const { operation } = openRequest(init, secrets);
        if (operation.type !== stalled && operation.type === "PublicKeys") {
          return lookupReply(init, secrets, operation.address);
        }
        controller.abort(new Error("operator deadline expired"));
        return new Promise<Response>(() => {});
      });
    vi.stubGlobal("fetch", fetch);
    await expect(probeNitroTarget(policy.targets[0]!, trust, { signal: controller.signal })).rejects.toThrow("operator deadline expired");
    expect(fetch).toHaveBeenCalledTimes(stalled === "PublicKeys" ? 2 : 3);
  });

  it.each(["attestation age", "certificate expiry", "elapsed time"])("discards a reply if %s invalidates the probe", async limit => {
    const { policy } = JSON.parse(signedPolicy()) as { policy: NitroPolicy };
    let wall = Date.now();
    let elapsed = 0;
    const time = vi.spyOn(Date, "now").mockImplementation(() => wall);
    const ticks = vi.spyOn(performance, "now").mockImplementation(() => elapsed);
    try {
      const discovery = attestedDiscovery(undefined, undefined, BigInt(wall) + (limit === "certificate expiry" ? 999n : 120_000n));
      if (limit === "attestation age") wall += 59_500;
      const fetch = vi.fn().mockResolvedValueOnce(discovery).mockImplementationOnce(async (_url, init: RequestInit) => {
        if (limit === "elapsed time") elapsed = 60_000;
        else wall += 1_000;
        const { operation } = openRequest(init, secrets);
        if (operation.type !== "PublicKeys") throw new Error("expected the first operation");
        return lookupReply(init, secrets, operation.address);
      });
      vi.stubGlobal("fetch", fetch);
      await expect(probeNitroTarget(policy.targets[0]!, trust)).rejects.toThrow("ExpiredRequest");
      expect(fetch).toHaveBeenCalledTimes(2);
    } finally {
      time.mockRestore();
      ticks.mockRestore();
    }
  });
});

describe("native client trust gate", () => {
  it("rejects an out-of-field nullifier key before asking the owner to sign", async () => {
    const viewing = ViewingKey.generate();
    const viewing_public_key = encodeLowerHex(viewing.publicKey().toBytes());
    viewing.destroy();
    const response = (init: RequestInit, nullifier_public_key: string) =>
      signedReply(openRequest(init, secrets), secrets, { type: "PublicKeys", viewing_public_key, nullifier_public_key });
    const lastFieldElement = (BigInt(BN254_MODULUS_DEC) - 1n).toString(16);
    const policy = signedPolicy();
    const fetch = policyHeads(vi.fn(), policy).mockResolvedValueOnce(attestedDiscovery())
      .mockImplementationOnce((_url, init) => response(init, nullifierModulus));
    policyHeads(fetch, policy).mockImplementationOnce((_url, init) => response(init, lastFieldElement));
    policyHeads(fetch, policy);
    vi.stubGlobal("fetch", fetch);
    const client = createNitroDecryptionService({ trust, policyStore: checkpointStore() });
    await expect(client.open(signer, proofs)).rejects.toMatchObject({ code: "InvalidPublicKey" });
    await expect(client.address(signer.address)).resolves.toMatchObject({
      nullifierPublicKey: requireHex(lastFieldElement, 32),
    });
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("requires the pinned boot before sending an operation or asking the owner to sign", async () => {
    const policy = signedPolicy();
    const discovery = await attestedDiscovery().json();
    const fetch = policyHeads(vi.fn(), policy).mockResolvedValueOnce(Response.json(discovery));
    policyHeads(fetch, policy).mockResolvedValueOnce(Response.json(discovery))
      .mockImplementationOnce((_url, init) => lookupReply(init, secrets));
    policyHeads(fetch, policy);
    vi.stubGlobal("fetch", fetch);
    const blocked = createNitroDecryptionService({ trust, policyStore: checkpointStore(), requiredBootKeyId: "42".repeat(32) });
    await expect(blocked.open(signer, proofs)).rejects.toThrow("no authorized Nitro replica");
    expect(signMessages).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(3);
    const allowed = createNitroDecryptionService({ trust, policyStore: checkpointStore(), requiredBootKeyId: discovery.boot.info.quorum_key_id });
    await expect(allowed.address(signer.address)).resolves.toBeDefined();
  });

  it("binds the bootstrap slots with the rest of the signed boot", async () => {
    const policy = signedPolicy();
    const response = await attestedDiscovery().json();
    const binding = sha256(new TextEncoder().encode("SPR/native-nitro/discovery/v1" + canonicalizeJsonValue(response.boot)));
    const verified = vi.mocked(verifyNativeNitroEvidence);
    verified.mockImplementation(async (_evidence, _nonce, received) => {
      if (encodeLowerHex(received) !== encodeLowerHex(binding)) throw new Error("wrong attestation binding");
      return { proofKey: publicPair(secrets), attestedAtMs: BigInt(Date.now()),
        certificateValidFromMs: 0n, certificateValidThroughMs: BigInt(Date.now()) + 60_000n };
    });
    const fetch = policyHeads(vi.fn(), policy).mockResolvedValueOnce(Response.json({
      ...response, boot: { ...response.boot, bootstrapSlots: [1, 3, 6] },
    }));
    policyHeads(fetch, policy).mockResolvedValueOnce(Response.json(response))
      .mockImplementationOnce((_url, init) => lookupReply(init, secrets));
    policyHeads(fetch, policy);
    vi.stubGlobal("fetch", fetch);
    const client = createNitroDecryptionService({ trust, policyStore: checkpointStore() });
    await expect(client.address(signer.address)).rejects.toThrow("no authorized Nitro replica");
    await expect(client.address(signer.address)).resolves.toBeDefined();
    expect(verified).toHaveBeenCalledTimes(2);
  });

  it.each([[1, 1, 3], [1, 3, 7], [1, 3], [1, 3, 4.5], [1, "3", 5]].map(slots => ({ slots })))(
    "rejects invalid bootstrap slots $slots", async ({ slots }) => {
    const response = await attestedDiscovery().json();
    const fetch = policyHeads().mockResolvedValueOnce(Response.json({
      ...response, boot: { ...response.boot, bootstrapSlots: slots },
    }));
    vi.stubGlobal("fetch", fetch);
    const client = createNitroDecryptionService({ trust, policyStore: checkpointStore() });
    await expect(client.address(signer.address)).rejects.toThrow("no authorized Nitro replica");
    expect(verifyNativeNitroEvidence).not.toHaveBeenCalled();
  });

  it("rejects a serving boot time later than its AWS attestation", async () => {
    const response = await attestedDiscovery().json();
    const fetch = policyHeads().mockResolvedValueOnce(Response.json({
      ...response, boot: { ...response.boot, bootedAtMs: String(Date.now() + 60_000) },
    }));
    vi.stubGlobal("fetch", fetch);
    await expect(createNitroDecryptionService({ trust, policyStore: checkpointStore() })
      .open(signer, proofs)).rejects.toThrow("no authorized Nitro replica");
    expect(verifyNativeNitroEvidence).toHaveBeenCalledOnce();
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("refuses payment addresses while the owner can still open and decrypt a recovery note", async () => {
    await initializePoseidon();
    const policy = signedPolicy({ recoveryOnly: true });
    const viewing = ViewingKey.generate();
    const viewingPublicKey = viewing.publicKey();
    viewing.destroy();
    const secret = new Uint8Array(31).fill(5) as Bytes31;
    const nullifier = NullifierKey.fromSecret(secret);
    const nullifierPublicKey = encodeLowerHex(nullifier.publicKey());
    nullifier.destroy();
    const fetch = vi.fn(async (url: URL, init: RequestInit) => {
      if (url.pathname.endsWith("/policy.json")) return new Response(policy);
      if (url.pathname === "/v1/nitro/attestation") return attestedDiscovery();
      const request = openRequest(init, secrets);
      if (request.operation.type === "PublicKeys") {
        return signedReply(request, secrets, { type: "PublicKeys", viewing_public_key: encodeLowerHex(viewingPublicKey.toBytes()),
          nullifier_public_key: nullifierPublicKey });
      }
      expect(request.operation).toMatchObject({ signer: signer.address, signature: "01".repeat(64) });
      return signedReply(request, secrets, { type: "Decrypt", nullifier_secret: encodeLowerHex(secret),
        plaintexts: request.operation.items.map(() => "aa") });
    });
    vi.stubGlobal("fetch", fetch);
    const store = checkpointStore();
    signMessages.mockResolvedValue([{ [signer.address]: signatureBytes(new Uint8Array(64).fill(1)) }]);
    const client = createNitroDecryptionService({ trust, policyStore: store });
    await expect(client.address(signer.address)).rejects.toMatchObject({ code: "ReleasePolicyRecoveryOnly" });
    expect(fetch.mock.calls.some(([url]) => url.pathname === "/v1/operations")).toBe(false);
    expect(await store.current()).toMatchObject({ recoveryOnly: true });
    const keys = await client.open(signer, { prove: vi.fn(), proveMerge: vi.fn() } as ProofService);
    try {
      const request = { ciphertext: Uint8Array.of(0x11), viewingPublicKey, txViewingPublicKey: viewingPublicKey,
        salt: new Uint8Array(16) as Bytes16, slotIndex: 0, label: "transfer" as const };
      await expect(keys.decrypt([request])).resolves.toEqual([Uint8Array.of(0xaa)]);
      expect(signMessages).toHaveBeenCalledTimes(2);
    } finally { keys.destroy(); }
  });

  it("records a recovery-only cutover while replicas are offline and rejects a later reopening", async () => {
    const recovery = signedPolicy({ recoveryOnly: true });
    const reopened = signedPolicy({ sequence: "3", previousPolicyDigest: encodeLowerHex(nitroPolicySigningDigest(JSON.parse(recovery).policy)) });
    const fetch = policyHeads(vi.fn(), recovery).mockResolvedValueOnce(new Response(null, { status: 503 }));
    policyHeads(fetch, reopened);
    vi.stubGlobal("fetch", fetch);
    const store = checkpointStore();
    const client = createNitroDecryptionService({ trust, policyStore: store });
    await expect(client.address(signer.address)).rejects.toMatchObject({ code: "BootProofUnverified" });
    expect(await store.current()).toMatchObject({ sequence: "2", recoveryOnly: true });
    const fresh = createNitroDecryptionService({ trust, policyStore: store });
    await expect(fresh.address(signer.address)).rejects.toThrow("policy rollback");
    expect(fetch.mock.calls.filter(([url]) => !url.pathname.endsWith("/policy.json"))).toHaveLength(1);
  });

  it("checks both published policies before a cached boot resolves a payment", async () => {
    const old = signedPolicy();
    const previousPolicyDigest = encodeLowerHex(nitroPolicySigningDigest(JSON.parse(old).policy));
    const recovery = signedPolicy({ sequence: "3", previousPolicyDigest, recoveryOnly: true });
    const fetch = policyHeads(vi.fn(), old).mockResolvedValueOnce(attestedDiscovery())
      .mockImplementationOnce((_url, init) => lookupReply(init, secrets));
    policyHeads(fetch, old);
    policyHeads(fetch, recovery, old);
    vi.stubGlobal("fetch", fetch);
    const store = checkpointStore();
    const client = createNitroDecryptionService({ trust, policyStore: store });
    await client.address(signer.address);
    await expect(client.address(signer.address)).rejects.toMatchObject({ code: "ReleasePolicyRecoveryOnly" });
    expect(await store.current()).toMatchObject({ sequence: "3", recoveryOnly: true });
    expect(fetch.mock.calls.filter(([url]) => url.pathname === "/v1/operations")).toHaveLength(1);
  });

  it.each([
    ["revocation", { action: "revoke", targets: [] }, { code: "ReleasePolicyRevoked" }],
    ["recovery-only activation", { recoveryOnly: true }, { code: "ReleasePolicyRecoveryOnly" }],
    ["publication outage", undefined, { code: "ReleasePolicyInvalid", status: 503 }],
  ] as const)("discards a valid payment lookup reply after %s", async (_event, update, error) => {
    const old = signedPolicy();
    const fetch = policyHeads(vi.fn(), old).mockResolvedValueOnce(attestedDiscovery())
      .mockImplementationOnce((_url, init) => lookupReply(init, secrets));
    if (update) {
      const previousPolicyDigest = encodeLowerHex(nitroPolicySigningDigest(JSON.parse(old).policy));
      policyHeads(fetch, signedPolicy({ sequence: "3", previousPolicyDigest, ...update }), old);
    } else {
      fetch.mockImplementation(async (url: URL) => {
        expect(url.pathname).toMatch(/\/policy\.json$/);
        return url.hostname.startsWith("release-peer.") ? new Response(null, { status: 503 }) : new Response(old);
      });
    }
    vi.stubGlobal("fetch", fetch);
    const store = checkpointStore();
    const client = createNitroDecryptionService({ trust, policyStore: store });
    await expect(client.address(signer.address)).rejects.toMatchObject(error);
    expect(await store.current()).toMatchObject({ sequence: update ? "3" : "2" });
    expect(fetch.mock.calls.filter(([url]) => url.pathname === "/v1/operations")).toHaveLength(1);
  });

  it("blocks a cached payment while a publisher is unavailable and retains the attested boot", async () => {
    const policy = signedPolicy();
    const fetch = policyHeads(vi.fn(), policy).mockResolvedValueOnce(attestedDiscovery())
      .mockImplementationOnce((_url, init) => lookupReply(init, secrets));
    policyHeads(fetch, policy);
    fetch.mockResolvedValueOnce(new Response(policy)).mockResolvedValueOnce(new Response(null, { status: 503 }));
    policyHeads(fetch, policy).mockImplementationOnce((_url, init) => lookupReply(init, secrets));
    policyHeads(fetch, policy);
    vi.stubGlobal("fetch", fetch);
    const client = createNitroDecryptionService({ trust, policyStore: checkpointStore() });
    await client.address(signer.address);
    await expect(client.address(signer.address)).rejects.toMatchObject({ code: "ReleasePolicyInvalid", status: 503 });
    await expect(client.address(signer.address)).resolves.toBeDefined();
    expect(fetch.mock.calls.filter(([url]) => url.pathname === "/v1/nitro/attestation")).toHaveLength(1);
    expect(fetch.mock.calls.filter(([url]) => url.pathname === "/v1/operations")).toHaveLength(2);
  });

  it.each(["activate", "revoke"] as const)(
    "refuses a release-only %s before replica contact, checkpoint writes or wallet approval", async action => {
      const policy = JSON.parse(signedPolicy(action === "activate" ? {} : { action, targets: [], recoveryOnly: true }));
      const fetch = policyHeads(vi.fn(), JSON.stringify({ ...policy, custodySignatures: [] }));
      const accept = vi.fn(async () => true);
      vi.stubGlobal("fetch", fetch);
      const client = createNitroDecryptionService({ trust, policyStore: { ...emptyStore, accept } });
      await expect(client.open(signer, proofs)).rejects.toThrow("ReleasePolicyInvalid");
      expect(fetch).toHaveBeenCalledTimes(2);
      expect(verifyNativeNitroEvidence).not.toHaveBeenCalled();
      expect(accept).not.toHaveBeenCalled();
      expect(signMessages).not.toHaveBeenCalled();
    });

  it.each([false, true])("reattests at certificate expiry with a boot pin set to %s", async pinned => {
    vi.useFakeTimers();
    try {
      const policy = signedPolicy();
      const validThrough = BigInt(Date.now()) + 1_000n;
      const initialDiscovery = attestedDiscovery(undefined, secrets, validThrough);
      const fetch = policyHeads(vi.fn(), policy)
        .mockResolvedValueOnce(initialDiscovery)
        .mockImplementationOnce((_url, init) => lookupReply(init, secrets));
      policyHeads(fetch, policy);
      policyHeads(fetch, policy).mockImplementationOnce(() => attestedDiscovery(undefined, replacementBoot))
        .mockImplementationOnce((_url, init) => lookupReply(init, replacementBoot));
      policyHeads(fetch, policy);
      vi.stubGlobal("fetch", fetch);
      const requiredBootKeyId = encodeLowerHex(sha256(requireHex(publicPair(secrets), 130)));
      const client = createNitroDecryptionService({
        trust, policyStore: checkpointStore(), ...(pinned ? { requiredBootKeyId } : {}),
      });
      await client.address(signer.address);
      vi.setSystemTime(Number(validThrough + 1n));
      const lookup = client.address(signer.address);
      if (pinned) await expect(lookup).rejects.toThrow("no authorized Nitro replica");
      else await lookup;
      expect(verifyNativeNitroEvidence).toHaveBeenCalledTimes(2);
      expect(fetch.mock.calls.map(([url]) => url.pathname).filter(path => !path.endsWith("policy.json"))).toEqual([
        "/v1/nitro/attestation", "/v1/operations", "/v1/nitro/attestation", ...(pinned ? [] : ["/v1/operations"]),
      ]);
    } finally { vi.useRealTimers(); }
  });

  it("requires a current certificate after the checkpoint write", async () => {
    vi.useFakeTimers();
    try {
      const store = checkpointStore();
      const validThrough = BigInt(Date.now()) + 1_000n;
      const fetch = policyHeads().mockResolvedValueOnce(attestedDiscovery(undefined, secrets, validThrough));
      vi.stubGlobal("fetch", fetch);
      const client = createNitroDecryptionService({ trust, policyStore: {
        current: store.current,
        async accept(update) {
          vi.setSystemTime(Number(validThrough + 1n));
          return store.accept(update);
        },
      } });
      await expect(client.address(signer.address)).rejects.toMatchObject({ code: "BootProofUnverified" });
      expect(fetch).toHaveBeenCalledTimes(3);
    } finally { vi.useRealTimers(); }
  });

  it("uses the healthy replica inside the caller deadline and cancels the stalled probe", async () => {
    vi.useFakeTimers();
    try {
      const policy = twoReplicas();
      const cancel = vi.fn();
      const fetch = vi.fn(async (url: URL, init: RequestInit) => {
        if (url.pathname.endsWith("/policy.json")) return new Response(policy);
        const winner = url.hostname === "replacement.example.com";
        if (url.pathname === "/v1/nitro/attestation") {
          return winner ? attestedDiscovery(undefined, replacementBoot) : new Response(new ReadableStream({ cancel }));
        }
        expect(winner).toBe(true);
        return lookupReply(init, replacementBoot);
      });
      vi.stubGlobal("fetch", fetch);
      const client = createNitroDecryptionService({ trust, policyStore: checkpointStore() });
      const result = expect(client.address(signer.address, { timeoutMs: 800 })).resolves.toBeDefined();
      await vi.advanceTimersByTimeAsync(800);
      await result;
      expect(cancel).toHaveBeenCalledOnce();
      expect(verifyNativeNitroEvidence).toHaveBeenCalledTimes(1);
      expect(signMessages).not.toHaveBeenCalled();
    } finally { vi.useRealTimers(); }
  });

  it("starts the next probe immediately after a fast failure", async () => {
    vi.useFakeTimers();
    try {
      const policy = twoReplicas();
      const fetch = vi.fn(async (url: URL, init: RequestInit) => {
        if (url.pathname.endsWith("/policy.json")) return new Response(policy);
        if (url.hostname !== "replacement.example.com") return new Response(null, { status: 503 });
        return url.pathname === "/v1/nitro/attestation" ? attestedDiscovery(undefined, replacementBoot)
          : lookupReply(init, replacementBoot);
      });
      vi.stubGlobal("fetch", fetch);
      const client = createNitroDecryptionService({ trust, policyStore: checkpointStore() });
      const result = expect(client.address(signer.address, { timeoutMs: 100 })).resolves.toBeDefined();
      await vi.advanceTimersByTimeAsync(100);
      await result;
      expect(verifyNativeNitroEvidence).toHaveBeenCalledTimes(1);
    } finally { vi.useRealTimers(); }
  });

  it("cancels the active probe and pending fallbacks when the caller leaves", async () => {
    vi.useFakeTimers();
    try {
      const policy = twoReplicas();
      const cancel = vi.fn();
      const fetch = vi.fn(async (url: URL) => url.pathname.endsWith("/policy.json")
        ? new Response(policy) : new Response(new ReadableStream({ cancel })));
      vi.stubGlobal("fetch", fetch);
      const client = createNitroDecryptionService({ trust, policyStore: checkpointStore() });
      const result = expect(client.address(signer.address, { timeoutMs: 100 })).rejects.toMatchObject({ name: "TimeoutError" });
      await vi.advanceTimersByTimeAsync(1000);
      await result;
      expect(fetch).toHaveBeenCalledTimes(3);
      expect(cancel).toHaveBeenCalledOnce();
      expect(signMessages).not.toHaveBeenCalled();
    } finally { vi.useRealTimers(); }
  });

  it("discards a reply from a different boot and retries the unsigned lookup on an attested replacement", async () => {
    const policy = twoReplicas();
    const fetch = vi.fn(async (url: URL, init: RequestInit) => {
      if (url.pathname.endsWith("/policy.json")) return new Response(policy);
      const boot = url.hostname === "replacement.example.com" ? replacementBoot : secrets;
      if (url.pathname === "/v1/nitro/attestation") return attestedDiscovery(undefined, boot);
      return boot === secrets
        ? signedReply(openRequest(init, secrets), replacementBoot, {
            type: "PublicKeys", viewing_public_key: "00", nullifier_public_key: "00",
          })
        : lookupReply(init, replacementBoot);
    });
    vi.stubGlobal("fetch", fetch);
    const client = createNitroDecryptionService({ trust, policyStore: checkpointStore() });
    await expect(client.address(signer.address)).resolves.toBeDefined();
    expect(verifyNativeNitroEvidence).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls.filter(([url]) => url.pathname === "/v1/operations").map(([url]) => url.hostname))
      .toEqual(["replica.example.com", "replacement.example.com"]);
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("retries an unsigned lookup once with fresh evidence after a replica stalls mid-response", async () => {
    vi.useFakeTimers();
    try {
      const policy = twoReplicas();
      const cancel = vi.fn();
      const fetch = vi.fn(async (url: URL, init: RequestInit) => {
        if (url.pathname.endsWith("/policy.json")) return new Response(policy);
        const next = url.origin === new URL(replacement).origin;
        const boot = next ? replacementBoot : secrets;
        if (url.pathname === "/v1/nitro/attestation") return attestedDiscovery(undefined, boot);
        if (!next) return new Response(new ReadableStream({ cancel }));
        return lookupReply(init, boot);
      });
      vi.stubGlobal("fetch", fetch);
      const client = createNitroDecryptionService({ trust, policyStore: checkpointStore() });
      const result = expect(client.address(signer.address)).resolves.toBeDefined();
      await vi.advanceTimersByTimeAsync(12_000);
      await result;
      expect(cancel).toHaveBeenCalledOnce();
      expect(fetch.mock.calls.map(([url]) => url.href).filter(url => !url.endsWith("policy.json"))).toEqual([
        "https://replica.example.com/v1/nitro/attestation", "https://replica.example.com/v1/operations",
        `${replacement}v1/nitro/attestation`, `${replacement}v1/operations`,
      ]);
      expect(verifyNativeNitroEvidence).toHaveBeenCalledTimes(2);
      expect(signMessages).not.toHaveBeenCalled();
    } finally { vi.useRealTimers(); }
  });

  it.each(["http", "binding"] as const)("never retransmits a signed decrypt after a %s failure", async failure => {
    const policy = twoReplicas();
    let requests = 0;
    const fetch = vi.fn(async (url: URL, init: RequestInit) => {
      if (url.pathname.endsWith("/policy.json")) return new Response(policy);
      const boot = url.hostname === "replica.example.com" ? secrets : replacementBoot;
      if (url.pathname === "/v1/nitro/attestation") return attestedDiscovery(undefined, boot);
      if (++requests === 2) {
        const { ciphertext } = JSON.parse(String(init.body)) as { ciphertext: string };
        const request = JSON.parse(new TextDecoder().decode(qosDecrypt(boot[0]!, requireHex(ciphertext)))) as ServiceRequest;
        expect(request.operation).toMatchObject({ type: "Decrypt", signature: "01".repeat(64) });
        return failure === "http" ? new Response(null, { status: 503 }) : signedReply(request, replacementBoot, {
          type: "Decrypt", nullifier_secret: "00".repeat(31), plaintexts: [],
        });
      }
      return lookupReply(init, boot);
    });
    vi.stubGlobal("fetch", fetch);
    signMessages.mockResolvedValueOnce([{ [signer.address]: signatureBytes(new Uint8Array(64).fill(1)) }]);
    const client = createNitroDecryptionService({ trust, policyStore: checkpointStore() });
    await expect(client.open(signer, proofs)).rejects.toMatchObject(failure === "http"
      ? { code: "OperationUnavailable", status: 503 } : { code: "BootProofUnverified" });
    expect(requests).toBe(2);
    expect(signMessages).toHaveBeenCalledOnce();
    await expect(client.address(signer.address)).resolves.toBeDefined();
    expect(fetch.mock.calls.filter(([url]) => url.pathname === "/v1/operations").at(-1)?.[0].href)
      .toBe(`${replacement}v1/operations`);
    expect(requests).toBe(3);
    expect(signMessages).toHaveBeenCalledOnce();
  });

  it.each([[400, 2], [408, 2], [503, 2], [429, 1]])("caps lookup attempts on HTTP %s at %s", async (status, attempts) => {
    const policy = twoReplicas();
    const fetch = vi.fn(async (url: URL) => {
      if (url.pathname.endsWith("/policy.json")) return new Response(policy);
      if (url.pathname === "/v1/nitro/attestation") return attestedDiscovery();
      return new Response(null, { status, headers: { "retry-after": "5" } });
    });
    vi.stubGlobal("fetch", fetch);
    const client = createNitroDecryptionService({ trust, policyStore: checkpointStore() });
    await expect(client.address(signer.address)).rejects.toMatchObject({ status, retryAfter: "5" });
    expect(fetch.mock.calls.filter(([url]) => url.pathname === "/v1/operations")).toHaveLength(attempts);
  });
  it("refuses to send an operation or request approval if the qualified checkpoint cannot persist", async () => {
    const fetch = policyHeads().mockResolvedValueOnce(attestedDiscovery());
    vi.stubGlobal("fetch", fetch);
    const stored = vi.fn(async () => false);
    const client = createNitroDecryptionService({ trust, policyStore: { ...emptyStore, accept: stored } });
    await expect(client.open(signer, proofs)).rejects.toThrow("policy rollback or checkpoint");
    expect(stored).toHaveBeenCalledOnce();
    expect(verifyNativeNitroEvidence).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls[0]?.[0].href).toBe(`https://release-test.s3.eu-north-1.amazonaws.com/spr-release/mainnet/${trust.securityDomainId}/policy.json`);
    expect(fetch.mock.calls[1]?.[0].href).toBe(`https://release-peer.s3.eu-west-1.amazonaws.com/spr-release/mainnet/${trust.securityDomainId}/policy.json`);
    for (const [index, publication] of trust.publications.entries()) {
      expect(new Headers(fetch.mock.calls[index]?.[1].headers).get("x-amz-expected-bucket-owner")).toBe(publication.account);
    }
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("requires a bounded, verified policy before attempting to persist or contact a replica", async () => {
    const fetch = vi.fn(async () => new Response("x".repeat(32_769)));
    vi.stubGlobal("fetch", fetch);
    const stored = vi.fn(async () => true);
    const client = createNitroDecryptionService({ trust, policyStore: { ...emptyStore, accept: stored } });
    await expect(client.open(signer, proofs)).rejects.toThrow("ResponseTooLarge");
    expect(stored).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("rejects unattested discovery before requesting a wallet signature", async () => {
    const fetch = policyHeads()
      .mockResolvedValueOnce(new Response('{"info":{},"evidence":"00"}'));
    vi.stubGlobal("fetch", fetch);
    const client = createNitroDecryptionService({ trust, policyStore: checkpointStore() });
    await expect(client.open(signer, proofs)).rejects.toThrow("no authorized Nitro replica");
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(fetch.mock.calls[2]?.[0].href).toBe("https://replica.example.com/v1/nitro/attestation");
    expect(fetch.mock.calls[2]?.[1]).toMatchObject({ redirect: "error", method: "POST" });
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("rejects discovery for a different custody record at the expected epoch", async () => {
    const fetch = policyHeads().mockResolvedValueOnce(attestedDiscovery("ab".repeat(32)));
    vi.stubGlobal("fetch", fetch);
    const store = checkpointStore();
    const accept = vi.fn(store.accept);
    const client = createNitroDecryptionService({ trust, policyStore: { ...store, accept } });
    await expect(client.open(signer, proofs)).rejects.toThrow("no authorized Nitro replica");
    expect(accept).toHaveBeenCalledOnce();
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("keeps a newer signed floor across restart when its replicas cannot attest", async () => {
    const old = signedPolicy();
    const prior = (JSON.parse(old) as { policy: NitroPolicy }).policy;
    const previousPolicyDigest = encodeLowerHex(nitroPolicySigningDigest(prior));
    const targets = prior.targets.map(target => ({ ...target, custodyEpoch: "2" }));
    const newer = signedPolicy({ sequence: "3", minimumCustodyEpoch: "2", targets, previousPolicyDigest });
    const fetch = policyHeads(vi.fn(), newer, old)
      .mockResolvedValueOnce(new Response(null, { status: 503 }));
    policyHeads(fetch, old);
    vi.stubGlobal("fetch", fetch);
    vi.stubGlobal("indexedDB", new IDBFactory());
    await expect(createNitroDecryptionService({ trust }).open(signer, proofs)).rejects.toThrow("no authorized Nitro replica");
    expect(await indexedDbNitroPolicyStore(trust).current()).toMatchObject({ sequence: "3", minimumCustodyEpoch: "2" });
    await expect(createNitroDecryptionService({ trust }).open(signer, proofs)).rejects.toThrow("policy rollback");
    expect(fetch.mock.calls.filter(([url]) => !url.pathname.endsWith("/policy.json"))).toHaveLength(1);
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("persists the same revocation from either bucket and refuses rollback before attestation after restart", async () => {
    const old = signedPolicy();
    const previousPolicyDigest = encodeLowerHex(nitroPolicySigningDigest(JSON.parse(old).policy));
    const revoked = signedPolicy({ action: "revoke", sequence: "3", previousPolicyDigest, minimumCustodyEpoch: "2", targets: [] });
    const fetch = policyHeads(vi.fn(), old, revoked);
    policyHeads(fetch, revoked, old);
    policyHeads(fetch, old);
    policyHeads(fetch, signedPolicy({ sequence: "4" }));
    vi.stubGlobal("fetch", fetch);
    vi.stubGlobal("indexedDB", new IDBFactory());
    const client = createNitroDecryptionService({ trust });
    const stored = indexedDbNitroPolicyStore(trust);
    await expect(client.open(signer, proofs)).rejects.toThrow("ReleasePolicyRevoked");
    const checkpoint = await stored.current();
    expect(checkpoint).toMatchObject({ sequence: "3", minimumCustodyEpoch: "2", revoked: true });
    await expect(client.open(signer, proofs)).rejects.toThrow("ReleasePolicyRevoked");
    expect(await stored.current()).toEqual(checkpoint);

    const reopened = createNitroDecryptionService({ trust });
    await expect(reopened.open(signer, proofs)).rejects.toThrow("policy rollback");
    await expect(reopened.open(signer, proofs)).rejects.toThrow("policy rollback");
    expect(await stored.current()).toEqual(checkpoint);
    expect(fetch).toHaveBeenCalledTimes(8);
    expect(verifyNativeNitroEvidence).not.toHaveBeenCalled();
    expect(signMessages).not.toHaveBeenCalled();
  });

  it.each(["activate", "revoke", "stale publications"] as const)(
    "refreshes a superseded unsigned lookup once with %s", async change => {
      const old = signedPolicy();
      const { policy } = JSON.parse(old) as { policy: NitroPolicy };
      const previousPolicyDigest = encodeLowerHex(nitroPolicySigningDigest(policy));
      const updated = signedPolicy({
        sequence: "3", previousPolicyDigest,
        ...(change === "activate"
          ? { targets: [{ ...policy.targets[0]!, endpoint: replacement }] }
          : { action: "revoke", targets: [] }),
      });
      let published = old;
      const fetch = vi.fn(async (url: URL, init: RequestInit) => {
        if (url.pathname.endsWith("/policy.json")) return new Response(published);
        const boot = url.origin === new URL(replacement).origin ? replacementBoot : secrets;
        if (url.pathname === "/v1/nitro/attestation") return attestedDiscovery(undefined, boot);
        return lookupReply(init, boot);
      });
      vi.stubGlobal("fetch", fetch);
      vi.stubGlobal("indexedDB", new IDBFactory());
      const oldClient = createNitroDecryptionService({ trust });
      const newClient = createNitroDecryptionService({ trust });
      await expect(oldClient.address(signer.address)).resolves.toBeDefined();
      published = updated;
      if (change === "activate") {
        await expect(newClient.address(signer.address)).resolves.toBeDefined();
      } else {
        await expect(newClient.address(signer.address)).rejects.toMatchObject({ code: "ReleasePolicyRevoked" });
      }
      if (change === "stale publications") published = old;
      fetch.mockClear();
      const lookup = oldClient.address(signer.address);
      if (change === "activate") await expect(lookup).resolves.toBeDefined();
      else await expect(lookup).rejects.toMatchObject({
        code: change === "revoke" ? "ReleasePolicyRevoked" : "ReleasePolicyInvalid",
      });
      expect(fetch.mock.calls.filter(([url]) => url.pathname.endsWith("/policy.json"))).toHaveLength(change === "activate" ? 4 : 2);
      const contacts = fetch.mock.calls.filter(([url]) => !url.pathname.endsWith("/policy.json")).map(([url]) => url.href);
      expect(contacts).toEqual(change === "activate" ? [
        `${replacement}v1/nitro/attestation`, `${replacement}v1/operations`,
      ] : []);
      expect(signMessages).not.toHaveBeenCalled();
    },
  );

  it("discards a signed approval superseded while the signer waits", async () => {
    const old = signedPolicy();
    const previousPolicyDigest = encodeLowerHex(nitroPolicySigningDigest(JSON.parse(old).policy));
    const revoked = signedPolicy({ sequence: "3", previousPolicyDigest, action: "revoke", targets: [] });
    const fetch = policyHeads(vi.fn(), old).mockResolvedValueOnce(attestedDiscovery())
      .mockImplementationOnce((_url, init) => lookupReply(init, secrets));
    policyHeads(fetch, old);
    policyHeads(fetch, revoked);
    vi.stubGlobal("fetch", fetch);
    vi.stubGlobal("indexedDB", new IDBFactory());
    const newClient = createNitroDecryptionService({ trust });
    signMessages.mockImplementationOnce(async () => {
      await expect(newClient.address(signer.address)).rejects.toMatchObject({ code: "ReleasePolicyRevoked" });
      return [{ [signer.address]: signatureBytes(new Uint8Array(64).fill(1)) }];
    });
    await expect(createNitroDecryptionService({ trust }).open(signer, proofs))
      .rejects.toMatchObject({ code: "ReleasePolicySuperseded" });
    expect(fetch).toHaveBeenCalledTimes(8);
    expect(fetch.mock.calls.filter(([url]) => url.pathname === "/v1/operations")).toHaveLength(1);
    expect(signMessages).toHaveBeenCalledOnce();
  });

  it("discards an old approval when storage is restored after the same client accepted revocation", async () => {
    const old = signedPolicy();
    const { policy } = JSON.parse(old) as { policy: NitroPolicy };
    const previousPolicyDigest = encodeLowerHex(nitroPolicySigningDigest(policy));
    const revoked = signedPolicy({ sequence: "3", previousPolicyDigest, action: "revoke", targets: [] });
    const fetch = policyHeads(vi.fn(), old).mockResolvedValueOnce(attestedDiscovery())
      .mockImplementationOnce((_url, init) => lookupReply(init, secrets));
    policyHeads(fetch, old);
    policyHeads(fetch, revoked);
    vi.stubGlobal("fetch", fetch);
    let stored: NitroPolicyCheckpoint | undefined;
    const client = createNitroDecryptionService({ trust, policyStore: {
      async current() { return stored; },
      async accept(update) { stored = update[0].checkpoint; return true; },
    } });
    signMessages.mockImplementationOnce(async () => {
      const older = stored;
      await expect(client.address(signer.address)).rejects.toMatchObject({ code: "ReleasePolicyRevoked" });
      expect(stored?.sequence).toBe("3");
      stored = older;
      return [{ [signer.address]: signatureBytes(new Uint8Array(64).fill(1)) }];
    });
    await expect(client.open(signer, proofs)).rejects.toMatchObject({ code: "ReleasePolicySuperseded" });
    expect(fetch.mock.calls.filter(([url]) => url.pathname === "/v1/operations")).toHaveLength(1);
  });

  it.each(["before signing", "after signing", "after the replica responds", "publisher outage", "current recovery policy"] as const)(
    "checks published policy for a cached owner approval %s", async phase => {
      await initializePoseidon();
      const nullifierSecret = new Uint8Array(31).fill(2) as Bytes31;
      const nullifier = NullifierKey.fromSecret(nullifierSecret);
      const nullifierPublicKey = encodeLowerHex(nullifier.publicKey());
      nullifier.destroy();
      const old = signedPolicy({ recoveryOnly: true });
      const previousPolicyDigest = encodeLowerHex(nitroPolicySigningDigest(JSON.parse(old).policy));
      const revoked = signedPolicy({ sequence: "3", previousPolicyDigest, action: "revoke", recoveryOnly: true, targets: [] });
      let published = old;
      let outage = false;
      let decrypts = 0;
      const fetch = vi.fn(async (url: URL, init: RequestInit) => {
        if (url.pathname.endsWith("/policy.json")) {
          if (outage && url.hostname.startsWith("release-peer.")) return new Response(null, { status: 503 });
          return new Response(published);
        }
        if (url.pathname === "/v1/nitro/attestation") return attestedDiscovery();
        const request = openRequest(init, secrets);
        if (request.operation.type === "PublicKeys") {
          if (phase === "before signing") published = revoked;
          if (phase === "publisher outage") outage = true;
          return lookupReply(init, secrets, signer.address, nullifierPublicKey);
        }
        decrypts++;
        if (phase === "after the replica responds") published = revoked;
        return signedReply(request, secrets, { type: "Decrypt", nullifier_secret: encodeLowerHex(nullifierSecret), plaintexts: [] });
      });
      vi.stubGlobal("fetch", fetch);
      const signingExpected = phase !== "before signing" && phase !== "publisher outage";
      if (signingExpected) {
        signMessages.mockImplementationOnce(async () => {
          if (phase === "after signing") published = revoked;
          return [{ [signer.address]: signatureBytes(new Uint8Array(64).fill(1)) }];
        });
      }
      const store = checkpointStore();
      const client = createNitroDecryptionService({ trust, policyStore: store });
      if (phase === "current recovery policy") {
        const keys = await client.open(signer, { prove: vi.fn(), proveMerge: vi.fn() });
        keys.destroy();
      } else {
        await expect(client.open(signer, proofs)).rejects.toMatchObject(phase === "publisher outage"
          ? { code: "ReleasePolicyInvalid", status: 503 }
          : { code: "ReleasePolicyRevoked" });
      }
      expect(signMessages).toHaveBeenCalledTimes(Number(signingExpected));
      expect(decrypts).toBe(phase === "after the replica responds" || phase === "current recovery policy" ? 1 : 0);
      expect(await store.current()).toMatchObject({ sequence: published === old ? "2" : "3", recoveryOnly: true });
    },
  );

  it.each(["fails", "succeeds"] as const)("observes a revocation during attestation when the first probe %s", async outcome => {
    const { policy } = JSON.parse(twoReplicas()) as { policy: NitroPolicy };
    const recoveryOnly = outcome === "succeeds";
    const old = signedPolicy({ ...policy, recoveryOnly });
    const previousPolicyDigest = encodeLowerHex(nitroPolicySigningDigest(JSON.parse(old).policy));
    const revoked = signedPolicy({ sequence: "3", previousPolicyDigest, action: "revoke", targets: [], recoveryOnly });
    let published = old;
    vi.stubGlobal("indexedDB", new IDBFactory());
    const oldClient = createNitroDecryptionService({ trust });
    const newClient = createNitroDecryptionService({ trust });
    const fetch = vi.fn(async (url: URL, init: RequestInit) => {
      if (url.pathname.endsWith("/policy.json")) return new Response(published);
      if (url.pathname === "/v1/nitro/attestation") {
        if (url.hostname === "replica.example.com") {
          published = revoked;
          await expect(newClient.address(signer.address)).rejects.toMatchObject({ code: "ReleasePolicyRevoked" });
          return recoveryOnly ? attestedDiscovery() : new Response(null, { status: 503 });
        }
        return attestedDiscovery(undefined, replacementBoot);
      }
      return lookupReply(init, replacementBoot);
    });
    vi.stubGlobal("fetch", fetch);
    await expect(oldClient.address(signer.address)).rejects.toMatchObject({ code: "ReleasePolicyRevoked" });
    expect(fetch.mock.calls.map(([url]) => url.href).filter(url => !url.endsWith("/policy.json")))
      .toEqual(["https://replica.example.com/v1/nitro/attestation"]);
    expect(signMessages).not.toHaveBeenCalled();
  });

  it("refreshes a cached recovery-only session after the shared checkpoint is revoked", async () => {
    const old = signedPolicy({ recoveryOnly: true });
    const previousPolicyDigest = encodeLowerHex(nitroPolicySigningDigest(JSON.parse(old).policy));
    const revoked = signedPolicy({ sequence: "3", previousPolicyDigest, action: "revoke", targets: [], recoveryOnly: true });
    const fetch = policyHeads(vi.fn(), old).mockResolvedValueOnce(attestedDiscovery());
    policyHeads(fetch, revoked);
    policyHeads(fetch, revoked);
    vi.stubGlobal("fetch", fetch);
    vi.stubGlobal("indexedDB", new IDBFactory());
    const client = createNitroDecryptionService({ trust });
    await expect(client.address(signer.address)).rejects.toMatchObject({ code: "ReleasePolicyRecoveryOnly" });
    await expect(createNitroDecryptionService({ trust }).address(signer.address))
      .rejects.toMatchObject({ code: "ReleasePolicyRevoked" });
    await expect(client.address(signer.address)).rejects.toMatchObject({ code: "ReleasePolicyRevoked" });
    expect(fetch.mock.calls.filter(([url]) => url.pathname === "/v1/operations")).toHaveLength(0);
  });

  it.each(["both clocks advance", "wall clock rolls back", "monotonic clock pauses"] as const)(
    "refreshes within 60 seconds of fetching policy when %s", async clocks => {
    const started = Date.now();
    let elapsed = 0;
    let wall = started;
    const time = vi.spyOn(Date, "now").mockImplementation(() => wall);
    const ticks = vi.spyOn(performance, "now").mockImplementation(() => elapsed);
    try {
      const old = signedPolicy();
      const previousPolicyDigest = encodeLowerHex(nitroPolicySigningDigest(JSON.parse(old).policy));
      const revoked = signedPolicy({ sequence: "3", previousPolicyDigest, action: "revoke", targets: [] });
      let published = old;
      const fetch = vi.fn(async (url: URL, init: RequestInit) => {
        if (url.pathname.endsWith("/policy.json")) {
          if (elapsed === 0) { elapsed = 2_000; wall = started + elapsed; }
          return new Response(published);
        }
        if (url.pathname === "/v1/nitro/attestation") {
          elapsed = 3_000;
          wall = started + elapsed;
          return attestedDiscovery();
        }
        return lookupReply(init, secrets);
      });
      vi.stubGlobal("fetch", fetch);
      const store = checkpointStore();
      const client = createNitroDecryptionService({ trust, policyStore: store });
      await client.address(signer.address);
      const advance = (milliseconds: number) => {
        elapsed = clocks === "monotonic clock pauses" ? 3_000 : milliseconds;
        wall = started + (clocks === "wall clock rolls back" ? 2_500 : milliseconds);
      };
      advance(59_999);
      await expect(client.address(signer.address)).resolves.toBeDefined();
      fetch.mockClear();
      published = revoked;
      advance(60_000);
      await expect(client.address(signer.address)).rejects.toMatchObject({ code: "ReleasePolicyRevoked" });
      expect(await store.current()).toMatchObject({ sequence: "3" });
      expect(fetch.mock.calls.map(([url]) => url.pathname)).toEqual([
        expect.stringMatching(/\/policy\.json$/), expect.stringMatching(/\/policy\.json$/),
      ]);
    } finally {
      ticks.mockRestore();
      time.mockRestore();
    }
  });

  it("discards owner approval returned after the monotonic policy window", async () => {
    let elapsed = 0;
    const ticks = vi.spyOn(performance, "now").mockImplementation(() => elapsed);
    try {
      const policy = signedPolicy();
      const fetch = policyHeads(vi.fn(), policy).mockResolvedValueOnce(attestedDiscovery())
        .mockImplementationOnce((_url, init) => lookupReply(init, secrets));
      policyHeads(fetch, policy);
      vi.stubGlobal("fetch", fetch);
      signMessages.mockImplementationOnce(async () => {
        elapsed = 60_000;
        return [{ [signer.address]: signatureBytes(new Uint8Array(64).fill(1)) }];
      });
      const client = createNitroDecryptionService({ trust, policyStore: checkpointStore() });
      await expect(client.open(signer, proofs)).rejects.toMatchObject({ code: "ExpiredRequest" });
      expect(signMessages).toHaveBeenCalledOnce();
      expect(fetch.mock.calls.filter(([url]) => url.pathname === "/v1/operations")).toHaveLength(1);
    } finally { ticks.mockRestore(); }
  });

  it("requires the second publication even if the first returned a usable signed policy", async () => {
    const fetch = vi.fn().mockResolvedValueOnce(new Response(signedPolicy()))
      .mockResolvedValueOnce(new Response(null, { status: 503 }));
    vi.stubGlobal("fetch", fetch);
    const accept = vi.fn(async () => true);
    const client = createNitroDecryptionService({ trust, policyStore: { ...emptyStore, accept } });
    await expect(client.open(signer, proofs)).rejects.toMatchObject({ code: "ReleasePolicyInvalid", status: 503 });
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(accept).not.toHaveBeenCalled();
    expect(signMessages).not.toHaveBeenCalled();
  });
});

it("refuses a fully signed direct successor of another bootstrap revision before touching storage", async () => {
  const wrong = signedPolicy({ previousPolicyDigest: "00".repeat(31) + "01" });
  const fetch = policyHeads(vi.fn(), wrong);
  vi.stubGlobal("fetch", fetch);
  const accept = vi.fn(async () => true);
  const client = createNitroDecryptionService({ trust, policyStore: { ...emptyStore, accept } });
  await expect(client.open(signer, proofs)).rejects.toMatchObject({ code: "ReleasePolicyInvalid" });
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(accept).not.toHaveBeenCalled();
  expect(signMessages).not.toHaveBeenCalled();
});

it.each(["mirror is ahead", "primary is unavailable", "mirror is unavailable"] as const)(
  "remembers an authenticated emergency revocation when the %s",
  async (failure) => {
    const active = signedPolicy();
    const previousPolicyDigest = encodeLowerHex(nitroPolicySigningDigest(JSON.parse(active).policy));
    const revoked = signedPolicy({ action: "revoke", sequence: "3", previousPolicyDigest, targets: [] });
    const fetch = policyHeads(vi.fn(), active).mockResolvedValueOnce(new Response(null, { status: 503 }));
    fetch.mockResolvedValueOnce(failure === "primary is unavailable" ? new Response(null, { status: 503 })
      : new Response(failure === "mirror is ahead" ? active : revoked));
    fetch.mockResolvedValueOnce(failure === "mirror is unavailable" ? new Response(null, { status: 503 })
      : new Response(revoked));
    policyHeads(fetch, active);
    vi.stubGlobal("fetch", fetch);
    vi.stubGlobal("indexedDB", new IDBFactory());
    const wallet = createNitroDecryptionService({ trust });
    await expect(wallet.address(signer.address)).rejects.toThrow("no authorized Nitro replica");
    await expect(wallet.open(signer, proofs)).rejects.toMatchObject({ code: "ReleasePolicyRevoked" });
    expect(await indexedDbNitroPolicyStore(trust).current()).toMatchObject({ sequence: "3", revoked: true });
    await expect(createNitroDecryptionService({ trust }).open(signer, proofs)).rejects.toThrow("policy rollback");
    expect(fetch.mock.calls.filter(([url]) => !url.pathname.endsWith("/policy.json"))).toHaveLength(1);
    expect(signMessages).not.toHaveBeenCalled();
  },
);

it("keeps a same-sequence emergency revocation and accepts a later agreed reconciliation", async () => {
  const active = signedPolicy();
  const revocation = signedPolicy({ action: "revoke", targets: [] });
  const activeDigest = encodeLowerHex(nitroPolicySigningDigest(JSON.parse(active).policy));
  const reconcile = signedPolicy({ action: "revoke", sequence: "3", previousPolicyDigest: activeDigest, targets: [] });
  const reconcileDigest = encodeLowerHex(nitroPolicySigningDigest(JSON.parse(reconcile).policy));
  const replacement = signedPolicy({ sequence: "4", previousPolicyDigest: reconcileDigest });
  const fetch = policyHeads(vi.fn(), active).mockResolvedValueOnce(new Response(null, { status: 503 }));
  policyHeads(fetch, active, revocation);
  policyHeads(fetch, active);
  policyHeads(fetch, reconcile);
  policyHeads(fetch, replacement, reconcile).mockResolvedValueOnce(new Response(null, { status: 503 }));
  vi.stubGlobal("fetch", fetch);
  vi.stubGlobal("indexedDB", new IDBFactory());
  const open = () => createNitroDecryptionService({ trust }).open(signer, proofs);
  const store = indexedDbNitroPolicyStore(trust);
  await expect(open()).rejects.toThrow("no authorized Nitro replica");
  await expect(open()).rejects.toMatchObject({ code: "ReleasePolicyRevoked" });
  expect(await store.current()).toMatchObject({ sequence: "2", revoked: true });
  expect((await store.current())?.digest).not.toBe(activeDigest);
  await expect(open()).rejects.toThrow("policy rollback");
  await expect(open()).rejects.toMatchObject({ code: "ReleasePolicyRevoked" });
  expect(await store.current()).toMatchObject({ sequence: "3", digest: reconcileDigest, revoked: true });
  await expect(open()).rejects.toThrow("no authorized Nitro replica");
  expect(await store.current()).toMatchObject({ sequence: "4" });
  expect((await store.current())?.revoked).toBeUndefined();
  expect(signMessages).not.toHaveBeenCalled();
});

it.each(["conflicting stops", "locally rejected activation"] as const)(
  "records the applicable revocation with %s",
  async (scenario) => {
    const { policy } = JSON.parse(signedPolicy()) as { policy: NitroPolicy };
    const targets = policy.targets.map(target => ({ ...target, custodyEpoch: "2" }));
    const active = signedPolicy({ minimumCustodyEpoch: "2", targets });
    const digest = (text: string) => encodeLowerHex(nitroPolicySigningDigest(JSON.parse(text).policy));
    const late = scenario === "conflicting stops";
    const stop = signedPolicy({
      sequence: late ? "3" : "2", previousPolicyDigest: late ? digest(active) : policy.previousPolicyDigest,
      minimumCustodyEpoch: "2", action: "revoke", targets: [],
    });
    const alternate = late
      ? signedPolicy({ sequence: "3", previousPolicyDigest: digest(active), action: "revoke", targets: [] })
      : signedPolicy({ sequence: "3", previousPolicyDigest: digest(stop), minimumCustodyEpoch: "2", targets });
    const fetch = policyHeads(vi.fn(), active).mockResolvedValueOnce(new Response(null, { status: 503 }));
    policyHeads(fetch, alternate, stop);
    policyHeads(fetch, active);
    vi.stubGlobal("fetch", fetch);
    vi.stubGlobal("indexedDB", new IDBFactory());
    const open = () => createNitroDecryptionService({ trust }).open(signer, proofs);
    await expect(open()).rejects.toThrow("no authorized Nitro replica");
    await expect(open()).rejects.toMatchObject({ code: "ReleasePolicyRevoked" });
    expect(await indexedDbNitroPolicyStore(trust).current()).toMatchObject({ digest: digest(stop), revoked: true });
    await expect(open()).rejects.toThrow("policy rollback");
    expect(signMessages).not.toHaveBeenCalled();
  },
);

it("does not checkpoint a one-sided revocation with incomplete approvals or an expired deadline", async () => {
  const active = signedPolicy();
  const { policy } = JSON.parse(active) as { policy: NitroPolicy };
  const previousPolicyDigest = encodeLowerHex(nitroPolicySigningDigest(policy));
  const next: Partial<NitroPolicy> = { action: "revoke", sequence: "3", previousPolicyDigest, targets: [] };
  const unsigned = JSON.parse(signedPolicy(next));
  unsigned.custodySignatures = [];
  const expired = signedPolicy({ ...next, targets: [], validFromMs: String(Date.now() - 2_000), expiresAtMs: String(Date.now() - 1_000) });
  const fetch = policyHeads(vi.fn(), active).mockResolvedValueOnce(new Response(null, { status: 503 }));
  for (const head of [JSON.stringify(unsigned), expired]) {
    fetch.mockResolvedValueOnce(new Response(null, { status: 503 })).mockResolvedValueOnce(new Response(head));
  }
  vi.stubGlobal("fetch", fetch);
  vi.stubGlobal("indexedDB", new IDBFactory());
  const open = () => createNitroDecryptionService({ trust }).open(signer, proofs);
  await expect(open()).rejects.toThrow("no authorized Nitro replica");
  const store = indexedDbNitroPolicyStore(trust);
  const checkpoint = await store.current();
  await expect(open()).rejects.toMatchObject({ code: "ReleasePolicyInvalid", status: 503 });
  await expect(open()).rejects.toMatchObject({ code: "ReleasePolicyInvalid", status: 503 });
  expect(await store.current()).toEqual(checkpoint);
  expect(signMessages).not.toHaveBeenCalled();
});

it("refuses signed replacements that contradict a checkpoint after restart", async () => {
  const policyDigest = (signed: string) => encodeLowerHex(nitroPolicySigningDigest(JSON.parse(signed).policy));
  const committed = signedPolicy();
  const other = signedPolicy({ targets: [], action: "revoke" });
  const unrelated = signedPolicy({ sequence: "3", previousPolicyDigest: policyDigest(other) });
  const next = signedPolicy({ sequence: "4", previousPolicyDigest: policyDigest(unrelated) });
  const fetch = policyHeads(vi.fn(), committed).mockResolvedValueOnce(new Response(null, { status: 503 }));
  policyHeads(fetch, unrelated);
  policyHeads(fetch, next, unrelated);
  vi.stubGlobal("fetch", fetch);
  vi.stubGlobal("indexedDB", new IDBFactory());
  await expect(createNitroDecryptionService({ trust }).address(signer.address)).rejects.toThrow("no authorized Nitro replica");
  const stored = indexedDbNitroPolicyStore(trust);
  const saved = await stored.current();
  expect(saved).toMatchObject({ sequence: "2", digest: policyDigest(committed) });
  const restored = createNitroDecryptionService({ trust });
  await expect(restored.open(signer, proofs)).rejects.toThrow("policy rollback");
  await expect(restored.open(signer, proofs)).rejects.toThrow("policy rollback");
  expect(await stored.current()).toEqual(saved);
  expect(fetch.mock.calls.filter(([url]) => !url.pathname.endsWith("/policy.json"))).toHaveLength(1);
  expect(signMessages).not.toHaveBeenCalled();
});
