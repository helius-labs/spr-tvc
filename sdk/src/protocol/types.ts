import type { API_VERSION } from "./constants.js";

/**
 * The Solana network the release serves.
 * Every check is equality with the network the checker expects.
 */
export type Network = "devnet" | "mainnet";

export type OperationKind = "ServicePublicKeys" | "ServiceDecrypt";

export type HealthResponse = {
  status: "Healthy";
};

export type ServiceInfo = {
  version: number;
  network: Network;
  security_domain_id: string;
  release_id: string;
  manifest_digest: string;
  executable_digest: string;
  quorum_public_key: string;
  quorum_key_id: string;
  quorum_key_epoch: string;
  ephemeral_public_key: string;
  supported_operations: OperationKind[];
  /** Maximum UTF-8 bytes of the entire encrypted HTTP request envelope. */
  max_encrypted_request_bytes: string;
  max_encrypted_response_bytes: string;
  proof_type: string;
};

export type ReleasePolicy = {
  version: typeof API_VERSION;
  releaseId: string;
  network: Network;
  tvcApplicationId: string;
  securityDomainId: string;
  acceptedManifestDigests: readonly string[];
  acceptedExecutableDigests: readonly string[];
  quorumKeyId: string;
  quorumKeyEpoch: string;
  quorumPublicKey: string;
  allowedOperations: readonly OperationKind[];
  /** Maximum UTF-8 bytes of the entire encrypted HTTP request envelope. */
  maxEncryptedRequestBytes: number;
  maxEncryptedResponseBytes: number;
  turnkeyTrustRootId: string;
  turnkeyProofSchemaVersions: readonly string[];
  validFromMs: string;
  expiresAtMs: string;
  revocationEpoch: string;
};

/** A release authority's 64-byte raw low-S P-256 signature, hex. */
export type ReleaseAuthoritySignature = {
  keyId: string;
  signature: string;
};

export type SignedReleasePolicy = {
  policy: ReleasePolicy;
  authoritySetId: string;
  signatures: readonly ReleaseAuthoritySignature[];
};

export type ReleaseAuthorityKey = {
  keyId: string;
  publicKey: string;
};

export type PinnedReleaseAuthorities = {
  authoritySetId: string;
  threshold: number;
  keys: readonly ReleaseAuthorityKey[];
  /** Policies below the epoch are revoked. */
  minimumRevocationEpoch: string;
};

export type DecryptLabel = "Transfer" | "RingDeposit";

/**
 * One ciphertext to open with the wallet's viewing key. The answer is the
 * cipher's output, which the caller decodes; the enclave interprets nothing.
 */
export type DecryptItem = {
  ciphertext: string;
  /** Which of the wallet's viewing keys opens it; the enclave holds one. */
  viewing_public_key: string;
  transaction_viewing_public_key: string;
  salt: string;
  /** Zero for a ring deposit, which carries one envelope. */
  slot_index: string;
  label: DecryptLabel;
};

/** One value the protocol derives from the nullifier secret. */
export const SERVICE_INFO_KEYS = [
  "version",
  "network",
  "security_domain_id",
  "release_id",
  "manifest_digest",
  "executable_digest",
  "quorum_public_key",
  "quorum_key_id",
  "quorum_key_epoch",
  "ephemeral_public_key",
  "supported_operations",
  "max_encrypted_request_bytes",
  "max_encrypted_response_bytes",
  "proof_type",
] as const;
