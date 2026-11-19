import { sha256 } from "@noble/hashes/sha256";
import { RELEASE_POLICY_DOMAIN, RESULT_DIGEST_DOMAIN } from "./constants.js";

const te = new TextEncoder();

export function domainSeparatedHash(domain: string, payload: Uint8Array): Uint8Array {
  const domainBytes = te.encode(domain);
  const input = new Uint8Array(domainBytes.length + 1 + payload.length);
  input.set(domainBytes, 0);
  input[domainBytes.length] = 0;
  input.set(payload, domainBytes.length + 1);
  return sha256(input);
}

export function resultDigest(encryptedResult: Uint8Array): Uint8Array {
  return domainSeparatedHash(RESULT_DIGEST_DOMAIN, encryptedResult);
}

export function releasePolicyDigest(policyJcs: Uint8Array): Uint8Array {
  return domainSeparatedHash(RELEASE_POLICY_DOMAIN, policyJcs);
}


/** Exact `WalletDescriptor` digest the provisioner signs. */
