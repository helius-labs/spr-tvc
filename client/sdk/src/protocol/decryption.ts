import { sha256 } from "@noble/hashes/sha256";

import { domainSeparatedHash } from "./digest.js";
import { DecryptionServiceError } from "./error.js";
import { encodeDecimalU64 } from "./decimal.js";
import { encodeLowerHex } from "./hex.js";
import { canonicalizeJsonValue } from "./jcs.js";
import type { DecryptItem, Network } from "./types.js";

export const SERVICE_PROOF_TYPE = "spr.tvc.decryption_service.v1";
const SERVICE_REQUEST_DIGEST_DOMAIN = "SPR_TVC_DECRYPTION_SERVICE_REQUEST_V1";
const DECRYPT_LABEL = "TSPP/decryption-service/decrypt/v1";
const VIEW_GRANT_LABEL = "TSPP/decryption-service/view-grant/v1";
const VIEW_GRANT_DIGEST_DOMAIN = "SPR_TVC_VIEW_GRANT_V1";
/** Longest accepted view-grant window. The enclave stores nothing, so expiry is the only revocation. */
export const MAX_VIEW_GRANT_MS = 30n * 60n * 1000n;

const te = new TextEncoder();

export type ServiceOperation =
  | { readonly type: "PublicKeys"; readonly address: string }
  | {
      readonly type: "Decrypt";
      readonly signer: string;
      /** The signer's signature over `decryptMessage`. */
      readonly signature: string;
      readonly items: readonly DecryptItem[];
      readonly grant?: ViewGrant;
    };

/** A capability the owner signs locally. The grantee attaches it to `Decrypt`. */
export type ViewGrant = {
  readonly owner: string;
  readonly grantee: string;
  readonly network: Network;
  readonly quorum_key_id: string;
  readonly quorum_key_epoch: string;
  readonly not_before_ms: string;
  readonly expiry_ms: string;
  readonly signature: string;
};

export type ServiceRequest = {
  readonly version: number;
  readonly request_id: string;
  readonly target_release_id: string;
  readonly target_manifest_digest: string;
  readonly target_executable_digest: string;
  readonly quorum_key_id: string;
  readonly quorum_key_epoch: string;
  readonly client_response_public_key: string;
  readonly operation: ServiceOperation;
};

export type ServiceResult =
  | {
      readonly type: "PublicKeys";
      readonly viewing_public_key: string;
      readonly nullifier_public_key: string;
    }
  | {
      readonly type: "Decrypt";
      readonly nullifier_secret: string;
      /** In the order of the request's `items`. */
      readonly plaintexts: readonly string[];
    };

/** The digest of a request without a `Decrypt`'s signature. */
export function serviceRequestDigest(request: ServiceRequest): Uint8Array {
  const operation: Record<string, unknown> = { ...request.operation };
  delete operation.signature;
  return domainSeparatedHash(
    SERVICE_REQUEST_DIGEST_DOMAIN,
    te.encode(canonicalizeJsonValue({ ...request, operation })),
  );
}

/** What an owner signs for one `Decrypt`: a Solana off-chain message v0 with one signer. */
export function decryptMessage(
  signer: Uint8Array,
  network: Network,
  requestDigest: Uint8Array,
): Uint8Array {
  const payload = te.encode(`${DECRYPT_LABEL}/${network}/${encodeLowerHex(requestDigest)}`);
  return offchainMessage(DECRYPT_LABEL, signer, payload);
}

/** `H(VIEW_GRANT_DIGEST_DOMAIN, JCS(grant))`, without the owner's signature. */
export function viewGrantDigest(grant: ViewGrant): Uint8Array {
  const { signature: _signature, ...signed } = grant;
  return domainSeparatedHash(VIEW_GRANT_DIGEST_DOMAIN, te.encode(canonicalizeJsonValue(signed)));
}

/** What the owner signs for a view grant: a Solana off-chain message v0 with one signer. */
export function viewGrantMessage(owner: Uint8Array, grantDigest: Uint8Array): Uint8Array {
  const payload = te.encode(`${VIEW_GRANT_LABEL}/${encodeLowerHex(grantDigest)}`);
  return offchainMessage(VIEW_GRANT_LABEL, owner, payload);
}

/** Accept `nowMs` inside `[notBeforeMs, expiryMs)` when the span is at most [`MAX_VIEW_GRANT_MS`]. */
export function acceptViewGrantWindow(notBeforeMs: bigint, expiryMs: bigint, nowMs: bigint): void {
  const span = expiryMs - notBeforeMs;
  if (span <= 0n || span > MAX_VIEW_GRANT_MS || nowMs < notBeforeMs || nowMs >= expiryMs) {
    throw new DecryptionServiceError("ExpiredRequest");
  }
}

export function viewGrantWire(input: {
  readonly owner: string;
  readonly grantee: string;
  readonly network: Network;
  readonly quorumKeyId: string;
  readonly quorumKeyEpoch: bigint;
  readonly notBeforeMs: bigint;
  readonly expiryMs: bigint;
  readonly signature?: Uint8Array;
}): ViewGrant {
  return {
    owner: input.owner,
    grantee: input.grantee,
    network: input.network,
    quorum_key_id: input.quorumKeyId,
    quorum_key_epoch: encodeDecimalU64(input.quorumKeyEpoch),
    not_before_ms: encodeDecimalU64(input.notBeforeMs),
    expiry_ms: encodeDecimalU64(input.expiryMs),
    signature: encodeLowerHex(input.signature ?? new Uint8Array(64)),
  };
}

function offchainMessage(label: string, signer: Uint8Array, payload: Uint8Array): Uint8Array {
  return Uint8Array.of(
    0xff,
    ...te.encode("solana offchain"),
    0,
    ...sha256(te.encode(label)),
    0,
    1,
    ...signer,
    payload.length & 0xff,
    payload.length >> 8,
    ...payload,
  );
}
