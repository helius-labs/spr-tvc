import { p256 } from "@noble/curves/p256";
import { describe, expect, it, vi } from "vitest";

import { signP256Message } from "../../src/crypto/p256.js";
import { qosEncrypt } from "../../src/crypto/qos.js";
import { API_VERSION, TVC_APP_PROOF_SCHEME } from "../../src/protocol/constants.js";
import { SERVICE_PROOF_TYPE } from "../../src/protocol/decryption.js";
import { resultDigest } from "../../src/protocol/digest.js";
import { DecryptionServiceError } from "../../src/protocol/error.js";
import { encodeLowerHex } from "../../src/protocol/hex.js";
import { canonicalizeJsonValue } from "../../src/protocol/jcs.js";
import type { ConnectedTvcRuntime } from "../../src/connection/connect.js";
import { sealedExchange, type Exchange } from "../../src/connection/operations.js";

const bytes = (value: number) => new Uint8Array(32).fill(value);
const signing = bytes(1);
const publicKey = (secret: Uint8Array) => encodeLowerHex(p256.getPublicKey(secret, false));
const quorum = publicKey(bytes(2)) + publicKey(bytes(3));
const ephemeral = publicKey(bytes(4)) + publicKey(signing);
const requestId = "aa".repeat(32);
const manifest = "bb".repeat(32);
const text = new TextEncoder();

function fixture() {
  const exchange: Exchange = {
    request: { request_id: requestId },
    requestDigest: bytes(5),
    responseSecret: bytes(6),
    operation: "ServicePublicKeys",
  };
  const result = canonicalizeJsonValue({ type: "PublicKeys" });
  const receiver = p256.getPublicKey(exchange.responseSecret, false);
  const ciphertext = qosEncrypt(receiver, text.encode(result));
  const payload = {
    type: SERVICE_PROOF_TYPE,
    version: API_VERSION,
    request_id: requestId,
    request_digest: encodeLowerHex(exchange.requestDigest),
    result_digest: encodeLowerHex(resultDigest(ciphertext)),
    operation: exchange.operation,
  };
  const proofPayload = canonicalizeJsonValue(payload);
  const proof = {
    scheme: TVC_APP_PROOF_SCHEME,
    public_key: ephemeral,
    proof_payload: proofPayload,
    signature: encodeLowerHex(signP256Message(signing, text.encode(proofPayload))),
  };
  const response = {
    version: API_VERSION, request_id: requestId,
    encrypted_result: encodeLowerHex(ciphertext), tvc_app_proof: proof,
  };
  const verifyOperationAppProof = vi.fn(async () => {});
  const context: ConnectedTvcRuntime = {
    backend: { endpoint: new URL("https://enclave.example") },
    info: {
      version: API_VERSION, network: "devnet", release_id: "current", security_domain_id: manifest,
      manifest_digest: manifest, executable_digest: manifest,
      quorum_public_key: quorum, quorum_key_id: "quorum", quorum_key_epoch: "1",
      supported_operations: [exchange.operation],
      max_encrypted_request_bytes: "262144", max_encrypted_response_bytes: "262144",
      proof_type: SERVICE_PROOF_TYPE,
    },
    transport: { fetch: async () => Response.json(response) },
    releasePolicyValidFromMs: 0n, releasePolicyExpiresAtMs: 2n, nowMs: () => 1n,
    trustVerifier: { verifyOperationAppProof },
  };
  function sign(payload: object) {
    const canonical = canonicalizeJsonValue(payload);
    proof.proof_payload = canonical;
    proof.signature = encodeLowerHex(signP256Message(signing, text.encode(canonical)));
  }
  function replyWith(key: Uint8Array, plaintext: string) {
    const ciphertext = qosEncrypt(key, text.encode(plaintext));
    response.encrypted_result = encodeLowerHex(ciphertext);
    sign({ ...payload, result_digest: encodeLowerHex(resultDigest(ciphertext)) });
  }
  return { context, exchange, result, response, proof, payload, sign, receiver, replyWith, verifyOperationAppProof };
}

describe("operation replies", () => {
  it("opens only a reply signed by the replica for this request and ciphertext", async () => {
    const f = fixture();
    await expect(sealedExchange(f.context, f.exchange)).resolves.toBe(f.result);
    expect(f.verifyOperationAppProof).toHaveBeenCalledWith(expect.objectContaining({ publicKey: ephemeral }), undefined);
  });

  it("refuses an authenticated reply if a newer checkpoint supersedes its session", async () => {
    const f = fixture();
    const requireCurrentCheckpoint = vi.fn<() => Promise<void>>()
      .mockResolvedValueOnce(undefined).mockRejectedValueOnce(new DecryptionServiceError("ReleasePolicySuperseded"));
    await expect(sealedExchange({ ...f.context, requireCurrentCheckpoint }, f.exchange))
      .rejects.toMatchObject({ code: "ReleasePolicySuperseded" });
    expect(requireCurrentCheckpoint).toHaveBeenCalledTimes(2);
    expect(f.verifyOperationAppProof.mock.invocationCallOrder[0])
      .toBeLessThan(requireCurrentCheckpoint.mock.invocationCallOrder[1]!);
  });

  it("rechecks the checkpoint immediately before sending the sealed request", async () => {
    const f = fixture();
    const fetch = vi.fn();
    const requireCurrentCheckpoint = vi.fn<() => Promise<void>>()
      .mockRejectedValueOnce(new DecryptionServiceError("ReleasePolicySuperseded"));
    await expect(sealedExchange({ ...f.context, transport: { fetch }, requireCurrentCheckpoint }, f.exchange))
      .rejects.toMatchObject({ code: "ReleasePolicySuperseded" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each(["hosted", "native"])("rejects a %s reply if proof verification crosses expiry", async backend => {
    const f = fixture();
    let now = 1n;
    f.verifyOperationAppProof.mockImplementationOnce(async () => { now = 3n; });
    const context = {
      ...f.context,
      nowMs: () => now,
      ...(backend === "native" ? { requireCurrentCheckpoint: async () => {} } : {}),
    };
    await expect(sealedExchange(context, f.exchange)).rejects.toMatchObject({ code: "ExpiredRequest" });
    expect(f.verifyOperationAppProof).toHaveBeenCalledOnce();
  });

  it("never sends an operation whose release window already expired", async () => {
    const f = fixture();
    const fetch = vi.fn(f.context.transport.fetch);
    await expect(sealedExchange({ ...f.context, transport: { fetch }, nowMs: () => 3n }, f.exchange))
      .rejects.toMatchObject({ code: "ExpiredRequest" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([
    ["type", "wrong"], ["version", API_VERSION + 1], ["request_id", "00".repeat(32)], ["request_digest", "00".repeat(32)],
    ["result_digest", "00".repeat(32)], ["operation", "ServiceDecrypt"],
  ])("rejects an attested proof with a wrong %s", async (field, value) => {
    const f = fixture();
    f.sign({ ...f.payload, [field]: value });
    await expect(sealedExchange(f.context, f.exchange)).rejects.toMatchObject({ code: "ReleaseBindingMismatch" });
  });

  it("rejects a response from another request and an oversized encrypted result", async () => {
    const wrong = fixture();
    wrong.response.request_id = "00".repeat(32);
    await expect(sealedExchange(wrong.context, wrong.exchange)).rejects.toMatchObject({ code: "ReleaseBindingMismatch" });
    expect(wrong.verifyOperationAppProof).not.toHaveBeenCalled();

    const oversized = fixture();
    oversized.response.encrypted_result = "00".repeat(262_145);
    await expect(sealedExchange(oversized.context, oversized.exchange)).rejects.toMatchObject({ code: "ResponseTooLarge" });
    expect(oversized.verifyOperationAppProof).not.toHaveBeenCalled();
  });

  it("rejects unsupported reply versions, malformed proof JSON, and the wrong scheme", async () => {
    const old = fixture();
    Object.assign(old.response, { version: API_VERSION + 1 });
    await expect(sealedExchange(old.context, old.exchange)).rejects.toMatchObject({ code: "ReleaseBindingMismatch" });

    const malformed = fixture();
    malformed.proof.proof_payload = " " + malformed.proof.proof_payload;
    await expect(sealedExchange(malformed.context, malformed.exchange)).rejects.toMatchObject({ code: "TurnkeyEvidenceInvalid" });

    const wrong = fixture();
    Object.assign(wrong.proof, { scheme: "SIGNATURE_SCHEME_TK_API_P256" });
    await expect(sealedExchange(wrong.context, wrong.exchange)).rejects.toMatchObject({ code: "TurnkeyEvidenceInvalid" });

    const extra = fixture();
    extra.sign({ ...extra.payload, sealed_seed_digest: "00".repeat(32) });
    await expect(sealedExchange(extra.context, extra.exchange)).rejects.toMatchObject({ code: "UnknownJsonField" });
  });

  it("rejects an invalid signature and refuses an unverified replica", async () => {
    const badSignature = fixture();
    badSignature.proof.signature = "00".repeat(64);
    await expect(sealedExchange(badSignature.context, badSignature.exchange)).rejects.toMatchObject({ code: "InvalidSignature" });
    expect(badSignature.verifyOperationAppProof).not.toHaveBeenCalled();

    const unverified = fixture();
    unverified.verifyOperationAppProof.mockRejectedValueOnce(new Error("unverified replica"));
    await expect(sealedExchange(unverified.context, unverified.exchange)).rejects.toThrow("unverified replica");
  });

  it("checks the signed ciphertext digest, envelope authentication, and canonical plaintext", async () => {
    const changed = fixture();
    changed.response.encrypted_result += "00";
    await expect(sealedExchange(changed.context, changed.exchange)).rejects.toMatchObject({ code: "ReleaseBindingMismatch" });

    const wrongReceiver = fixture();
    wrongReceiver.replyWith(p256.getPublicKey(bytes(7), false), wrongReceiver.result);
    await expect(sealedExchange(wrongReceiver.context, wrongReceiver.exchange)).rejects.toMatchObject({ code: "InvalidEncryptedEnvelope" });

    const noncanonical = fixture();
    noncanonical.replyWith(noncanonical.receiver, " " + noncanonical.result);
    await expect(sealedExchange(noncanonical.context, noncanonical.exchange)).rejects.toMatchObject({ code: "InvalidCanonicalJson" });
  });
});
