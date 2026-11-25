export const API_VERSION = 1;

/** One SPR indexer page. An empty page fits in the encrypted body cap. */
export const NOTES_PER_SIGNATURE = 1000;
/** Photon's body cap, and the SPR SDK indexer client's. Pinned by `protocol/fixtures/page-limit.json`. */
export const MAX_ENCRYPTED_REQUEST_BYTES = 10 * 1024 * 1024;
export const MAX_ENCRYPTED_RESPONSE_BYTES = MAX_ENCRYPTED_REQUEST_BYTES;
export const EXPECTED_TURNKEY_TRUST_ROOT_ID = "aws-nitro-root-g1";
export const TVC_APP_PROOF_SCHEME = "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256";
export const TVC_QOS_PING_PROOF_TYPE = "spr.tvc.qos_ping.v1";
export const TVC_APP_PROOF_KEYS = ["scheme", "public_key", "proof_payload", "signature"] as const;

export const RESULT_DIGEST_DOMAIN = "SPR_TVC_RESULT_V1";
export const RELEASE_POLICY_DOMAIN = "SPR_TVC_RELEASE_POLICY_V1";

export const MAX_CLOCK_SKEW_MS = 60_000n;

export const QOS_P256_PUBLIC_LEN = 130;
export const SEC1_UNCOMPRESSED_LEN = 65;
export const RAW_P256_SIGNATURE_LEN = 64;
export const AES_GCM_NONCE_LEN = 12;
export const AES_GCM_TAG_LEN = 16;
export const SHA256_LEN = 32;
export const SHA384_LEN = 48;
export const QOS_ENCRYPTION_HMAC_MESSAGE = "qos_encryption_hmac_message";
