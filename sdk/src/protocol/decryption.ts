import { sha256 } from "@noble/hashes/sha256";

import { domainSeparatedHash } from "./digest.js";
import { encodeLowerHex } from "./hex.js";
import { canonicalizeJsonValue } from "./jcs.js";
import type { DecryptItem, Network } from "./types.js";

export const SERVICE_PROOF_TYPE = "spr.tvc.decryption_service.v1";
const SERVICE_REQUEST_DIGEST_DOMAIN = "SPR_TVC_DECRYPTION_SERVICE_REQUEST_V1";
const VIEW_GRANT_DIGEST_DOMAIN = "SPR_TVC_VIEW_GRANT_V1";
const DECRYPT_LABEL = "TSPP/decryption-service/decrypt/v1";
const VIEW_GRANT_LABEL = "TSPP/decryption-service/view-grant/v1";

export const MAX_VIEW_GRANT_WINDOW_MS = 30 * 60 * 1000;

const te = new TextEncoder();

/** A capability the derivation owner signs. The grantee attaches it to `Decrypt`. */
export type ViewGrant = {
  readonly derivation: string;
  readonly grantee: string;
  readonly network: Network;
  readonly quorum_key_id: string;
  readonly quorum_key_epoch: string;
  readonly not_before: string;
  readonly expiry: string;
  /** The derivation owner's signature over `viewGrantMessage`. */
  readonly signature: string;
};

export type ServiceOperation =
  | { readonly type: "PublicKeys"; readonly address: string }
  | {
      readonly type: "Decrypt";
      /** Address whose service keys open `items`. */
      readonly derivation: string;
      /** `derivation`, or the grantee named by `grant`. */
      readonly signer: string;
      readonly grant?: ViewGrant;
      /** The signer's signature over `decryptMessage`. */
      readonly signature: string;
      readonly items: readonly DecryptItem[];
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

/** What `signer` signs for one `Decrypt`: a Solana off-chain message v0 with one signer. */
export function decryptMessage(
  signer: Uint8Array,
  network: Network,
  requestDigest: Uint8Array,
): Uint8Array {
  const payload = te.encode(`${DECRYPT_LABEL}/${network}/${encodeLowerHex(requestDigest)}`);
  return offchainMessage(DECRYPT_LABEL, signer, payload);
}

/** Digest of a view grant with its signature removed. */
export function viewGrantDigest(grant: ViewGrant): Uint8Array {
  const body: Record<string, unknown> = { ...grant };
  delete body.signature;
  return domainSeparatedHash(VIEW_GRANT_DIGEST_DOMAIN, te.encode(canonicalizeJsonValue(body)));
}

/** What the derivation owner signs for one view grant. */
export function viewGrantMessage(owner: Uint8Array, grantDigest: Uint8Array): Uint8Array {
  const payload = te.encode(`${VIEW_GRANT_LABEL}/${encodeLowerHex(grantDigest)}`);
  return offchainMessage(VIEW_GRANT_LABEL, owner, payload);
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
