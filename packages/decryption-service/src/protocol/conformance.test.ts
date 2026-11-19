import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256 } from "@noble/hashes/sha256";
import { describe, expect, it } from "vitest";
import { canonicalizeJsonValue, isRfc8785 } from "./jcs.js";
import { decodeDecimalU64, encodeDecimalU64 } from "./decimal.js";
import { decodeLowerHex, encodeLowerHex } from "./hex.js";
import { parseStrictJson } from "./json.js";
import { resultDigest } from "./digest.js";
import { DecryptionServiceError } from "./error.js";
import type { HealthResponse, ServiceInfo } from "./types.js";
import { SERVICE_INFO_KEYS } from "./types.js";
import {
  parseUncompressedSec1,
  verifyP256Message,
  verifyP256Prehash,
} from "../crypto/p256.js";
import {
  parseQosP256Public,
  qosDecrypt,
  qosEncryptWith,
} from "../crypto/qos.js";
import {
  computeQosLiveManifestCommitmentPcr,
  verifyBootProof,
} from "../verify/index.js";
import { connectAndVerifyTvc } from "../client/connection.js";
import {
  bindDiscoveryToPolicy,
  verifySignedReleasePolicy,
} from "../verify/release-policy.js";
import type {
  Network,
  PinnedReleaseAuthorities,
  SignedReleasePolicy,
} from "./types.js";

const fixturesDir = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/protocol/fixtures"
);

function readFixture(name: string): string {
  return readFileSync(join(fixturesDir, name), "utf8");
}

function readJson(name: string): Record<string, unknown> {
  return JSON.parse(readFixture(name)) as Record<string, unknown>;
}

const HEALTH_KEYS = ["status"] as const;

describe("content-addressed fixtures", () => {
  it("matches MANIFEST sha256 for every file", () => {
    const manifest = JSON.parse(readFixture("MANIFEST.json")) as {
      files: Record<string, string>;
    };
    for (const [name, digest] of Object.entries(manifest.files)) {
      const body = readFixture(name);
      expect(encodeLowerHex(sha256(new TextEncoder().encode(body)))).toBe(
        digest
      );
    }
  });
});

describe("RFC 8785 / JCS", () => {
  it("matches the Rust object-sort fixture", () => {
    const fixture = readJson("jcs-object-sort.json");
    expect(canonicalizeJsonValue(fixture.input)).toBe(fixture.canonical_json);
    expect(
      encodeLowerHex(
        sha256(new TextEncoder().encode(String(fixture.canonical_json)))
      )
    ).toBe(fixture.canonical_sha256);
  });
});

describe("canonical u64", () => {
  it("encodes the Rust vectors and rejects negatives", () => {
    const fixture = readJson("canonical-u64.json") as {
      values: { input: string; encoded: string }[];
      negative: string[];
    };
    for (const row of fixture.values) {
      const input = BigInt(row.input);
      expect(encodeDecimalU64(input)).toBe(row.encoded);
      expect(decodeDecimalU64(row.encoded)).toBe(input);
    }
    for (const bad of fixture.negative) {
      expect(() => decodeDecimalU64(bad)).toThrowError(DecryptionServiceError);
    }
  });
});

describe("P-256 signatures", () => {
  it("accepts raw low-S and rejects DER, high-S, compressed keys, and double hashing", () => {
    const fixture = readJson("p256-signatures.json");
    const publicKey = decodeLowerHex(String(fixture.public_key));
    const digest = decodeLowerHex(String(fixture.digest));
    const raw = decodeLowerHex(String(fixture.raw_low_s));
    verifyP256Prehash(publicKey, digest, raw);
    verifyP256Message(publicKey, new TextEncoder().encode(String(fixture.message)), raw);
    expect(() =>
      verifyP256Prehash(publicKey, digest, decodeLowerHex(String(fixture.der)))
    ).toThrowError(/DerSignatureRejected/);
    expect(() =>
      verifyP256Prehash(
        publicKey,
        digest,
        decodeLowerHex(String(fixture.high_s))
      )
    ).toThrowError(/HighSSignature/);
    expect(() =>
      parseUncompressedSec1(
        decodeLowerHex(String(fixture.compressed_public_key))
      )
    ).toThrowError(/CompressedKeyRejected/);
    // A signature over SHA-256(digest) is not a signature over digest.
    expect(() =>
      verifyP256Prehash(
        publicKey,
        digest,
        decodeLowerHex(String(fixture.double_hash_signature))
      )
    ).toThrowError(/^InvalidSignature$/);
  });
});

describe("QOS envelope", () => {
  it("parses the 130-byte public key and matches the Borsh envelope", () => {
    const pub = readJson("qos-p256-public.json");
    const parsed = parseQosP256Public(decodeLowerHex(String(pub.public_key)));
    expect(parsed.encryption.length).toBe(65);
    expect(parsed.signing.length).toBe(65);
    expect(encodeLowerHex(parsed.encryption)).toBe(pub.encryption_sec1);
    const envelope = readJson("qos-borsh-envelope.json");
    const produced = qosEncryptWith(
      decodeLowerHex(String(envelope.receiver_encryption_public)),
      decodeLowerHex(String(envelope.plaintext)),
      decodeLowerHex(String(envelope.ephemeral_secret)),
      decodeLowerHex(String(envelope.nonce))
    );
    expect(encodeLowerHex(produced)).toBe(envelope.envelope);
  });

  it("rejects truncated ciphertext and the wrong receiver key", () => {
    const fixture = readJson("qos-negative.json");
    const envelope = decodeLowerHex(String(fixture.envelope));
    const truncated = decodeLowerHex(String(fixture.truncated_envelope));
    const wrong = decodeLowerHex(String(fixture.wrong_receiver_secret));
    expect(() => qosDecrypt(wrong, envelope)).toThrowError(
      /InvalidEncryptedEnvelope/
    );
    expect(() => qosDecrypt(wrong, truncated)).toThrowError(
      /InvalidEncryptedEnvelope/
    );
  });
});

describe("JSON reject", () => {
  it("rejects unknown and duplicate fields", () => {
    const fixture = readJson("json-reject.json");
    expect(() =>
      parseStrictJson<HealthResponse>(
        String(fixture.unknown_field),
        HEALTH_KEYS
      )
    ).toThrowError(/UnknownJsonField/);
    expect(() =>
      parseStrictJson<HealthResponse>(
        String(fixture.duplicate_field),
        HEALTH_KEYS
      )
    ).toThrowError(/DuplicateJsonField/);
  });
});

describe("bindings and HTTP skeleton", () => {
  function discoveryFixtures() {
    const info = parseStrictJson<ServiceInfo>(
      String(readJson("http-skeleton.json").info_body),
      SERVICE_INFO_KEYS
    );
    const signed = readJson("signed-release-policy.json")
      .signed as SignedReleasePolicy;
    return { info, signed };
  }

  it("accepts discovery that matches the pinned policy", () => {
    const { info, signed } = discoveryFixtures();
    expect(() => bindDiscoveryToPolicy(info, signed)).not.toThrow();
  });

  it("rejects every discovery drift case the Rust binder rejects", () => {
    const fixture = readJson("discovery-binding.json");
    const signed = {
      policy: fixture.policy,
      authoritySetId: "fixture",
      signatures: [],
    } as SignedReleasePolicy;
    expect(() =>
      bindDiscoveryToPolicy(fixture.info as ServiceInfo, signed)
    ).not.toThrow();
    const cases = fixture.cases as {
      name: string;
      info: ServiceInfo;
      error: string;
    }[];
    expect(cases.length).toBe(14);
    for (const { name, info, error } of cases) {
      expect(() => bindDiscoveryToPolicy(info, signed), name).toThrowError(
        new RegExp(error)
      );
    }
  });

  it("treats /health as readiness-only and /v1/info as untrusted discovery", () => {
    const fixture = readJson("http-skeleton.json");
    expect(fixture.health_body).toBe('{"status":"Healthy"}');
    expect(fixture.health_has_release_id).toBe(false);
    const info = parseStrictJson<ServiceInfo>(
      String(fixture.info_body),
      SERVICE_INFO_KEYS
    );
    expect(info.release_id).toBe("tvc-dev-phase0");
  });
});

describe("proof payload UTF-8", () => {
  const fixture = readJson("proof-payload-utf8.json");
  const signing = parseQosP256Public(decodeLowerHex(String(fixture.public_key))).signing;
  const verify = (payload: unknown, signature: unknown) =>
    verifyP256Message(
      signing,
      new TextEncoder().encode(String(payload)),
      decodeLowerHex(String(signature)),
    );

  it("preserves exact bytes and verifies the App Proof", () => {
    const payload = String(fixture.proof_payload);
    expect(encodeLowerHex(new TextEncoder().encode(payload))).toBe(
      fixture.proof_payload_hex
    );
    expect(isRfc8785(payload)).toBe(true);
    verify(payload, fixture.signature);
    expect(() => verify(payload, fixture.non_jcs_signature)).toThrowError(/^InvalidSignature$/);
  });

  it("refuses the high-S form and a non-JCS payload on the App Proof path", () => {
    expect(() => verify(fixture.proof_payload, fixture.high_s_signature)).toThrowError(
      /HighSSignature/,
    );
    expect(isRfc8785(String(fixture.non_jcs_payload))).toBe(false);
  });
});

it("matches the Rust encrypted-result digest", () => {
  const fixture = readJson("digests.json");
  expect(encodeLowerHex(resultDigest(new TextEncoder().encode("encrypted-result")))).toBe(fixture.result_digest);
});

describe("signed release policy", () => {
  const fixture = readJson("signed-release-policy.json");
  const authorities = fixture.authorities as PinnedReleaseAuthorities;
  const network = fixture.network as Network;
  const nowMs = BigInt(String(fixture.now_ms));

  it("accepts the 1-of-3 signature for its network", () => {
    expect(() =>
      verifySignedReleasePolicy(
        fixture.signed as SignedReleasePolicy,
        authorities,
        network,
        nowMs
      )
    ).not.toThrow();
  });

  it("matches the Rust error code for another network", () => {
    expect(() =>
      verifySignedReleasePolicy(
        fixture.signed as SignedReleasePolicy,
        authorities,
        fixture.wrong_network_expected as Network,
        nowMs
      )
    ).toThrowError(new RegExp(String(fixture.wrong_network)));
  });

  // Each case runs the same input Rust ran and must reach the same error code.
  it.each([
    ["empty_signatures", "empty_signatures_input"],
    ["duplicate_key_id", "duplicate_key_id_input"],
    ["unknown_key_id", "unknown_key_id_input"],
    ["mutated_policy", "mutated_policy_input"],
    ["wrong_trust_root", "wrong_trust_root_input"],
  ])("matches the Rust error code for %s", (expected, inputKey) => {
    expect(() =>
      verifySignedReleasePolicy(
        fixture[inputKey] as SignedReleasePolicy,
        authorities,
        network,
        nowMs
      )
    ).toThrowError(new RegExp(String(fixture[expected])));
  });

  it("matches the Rust error code for a revoked epoch", () => {
    expect(() =>
      verifySignedReleasePolicy(
        fixture.signed as SignedReleasePolicy,
        fixture.revoked_epoch_authorities as PinnedReleaseAuthorities,
        network,
        nowMs
      )
    ).toThrowError(new RegExp(String(fixture.revoked_epoch)));
  });

  it("matches the Rust error code for a zero threshold", () => {
    expect(() =>
      verifySignedReleasePolicy(
        fixture.signed as SignedReleasePolicy,
        fixture.zero_threshold_authorities as PinnedReleaseAuthorities,
        network,
        nowMs
      )
    ).toThrowError(new RegExp(String(fixture.zero_threshold)));
  });

  it("matches the Rust error code for an expired policy", () => {
    expect(() =>
      verifySignedReleasePolicy(
        fixture.signed as SignedReleasePolicy,
        authorities,
        network,
        BigInt(String(fixture.expired_now_ms))
      )
    ).toThrowError(new RegExp(String(fixture.expired)));
  });

});

describe("enclave verification", () => {
  const PCRS = { 0: "44".repeat(48), 1: "55".repeat(48), 2: "66".repeat(48), 3: "77".repeat(48) };

  it("rejects an unsigned policy before Boot Proof", async () => {
    const policyFixture = readJson("signed-release-policy.json");
    const signed = structuredClone(
      policyFixture.signed
    ) as SignedReleasePolicy;
    signed.signatures = [];
    const verified = connectAndVerifyTvc({
      network: "devnet",
      backend: { endpoint: new URL("https://tvc.example.invalid") },
      release: {
        releasePolicy: signed,
        releaseAuthorities: policyFixture.authorities as PinnedReleaseAuthorities,
        qosIdentityPcrs: PCRS,
      },
      nowMs: () => BigInt(String(policyFixture.now_ms)),
      transport: {
        fetch: async () => {
          throw new Error("unsigned policy must not fetch discovery");
        },
      },
    });
    await expect(verified).rejects.toMatchObject({
      code: "ReleasePolicyInvalid",
    });
  });

  it("fails closed when a replica proves nothing after a valid policy", async () => {
    const http = readJson("http-skeleton.json");
    const policyFixture = readJson("signed-release-policy.json");
    const verified = connectAndVerifyTvc({
      network: "devnet",
      backend: { endpoint: new URL("https://tvc.example.invalid") },
      release: {
        releasePolicy: policyFixture.signed as SignedReleasePolicy,
        releaseAuthorities: policyFixture.authorities as PinnedReleaseAuthorities,
        qosIdentityPcrs: PCRS,
      },
      nowMs: () => BigInt(String(policyFixture.now_ms)),
      transport: {
        fetch: async (url) =>
          url.pathname === "/v1/info"
            ? new Response(String(http.info_body), {
                status: 200,
                headers: { "content-type": "application/json" },
              })
            : new Response(null, { status: 503 }),
      },
    });
    await expect(verified).rejects.toMatchObject({
      code: "BootProofUnverified",
    });
    await expect(verifyBootProof({} as never)).rejects.toThrowError(
      /BootProofUnverified/
    );
  });
});

describe("QOS live manifest PCR commitment", () => {
  // Derived from qos_nsm `nitro::LIVE_MANIFEST_COMMITMENT_PCR_INDEX` (17),
  // domain "qos-live-manifest-pcr-commitment-v1", extended from
  // MANIFEST_COMMITMENT_INITIAL_PCR ([0u8; 48]).
  it("matches the qos_nsm live-manifest PCR commitment", () => {
    const manifestDigest = new Uint8Array(32);
    const ephemeralPublicKey = new Uint8Array(130).fill(0x11);
    ephemeralPublicKey[0] = 0x04;
    expect(
      encodeLowerHex(
        computeQosLiveManifestCommitmentPcr(manifestDigest, ephemeralPublicKey)
      )
    ).toBe(
      "d19443155765a0795affb170c1e13a2360ea38202a5fa703950261f3d0a0c2321dd0ae2b8d7c9d1798d6898b1e25a94c"
    );
  });
});
