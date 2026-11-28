export const API_VERSION = 1;

/** One SPR indexer page. An empty page fits in the encrypted body cap. */
export const NOTES_PER_SIGNATURE = 1000;
/** Photon's body cap, and the SPR SDK indexer client's. Pinned by `wire/fixtures/page-limit.json`. */
export const MAX_ENCRYPTED_REQUEST_BYTES = 10 * 1024 * 1024;
export const MAX_ENCRYPTED_RESPONSE_BYTES = MAX_ENCRYPTED_REQUEST_BYTES;
export const EXPECTED_TURNKEY_TRUST_ROOT_ID = "aws-nitro-root-g1";
export const TVC_APP_PROOF_SCHEME = "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256";
export const TVC_QOS_PING_PROOF_TYPE = "spr.tvc.qos_ping.v1";
export const TVC_APP_PROOF_KEYS = ["scheme", "public_key", "proof_payload", "signature"] as const;

export const RESULT_DIGEST_DOMAIN = "SPR_TVC_RESULT_V1";
export const RELEASE_POLICY_DOMAIN = "SPR_TVC_RELEASE_POLICY_V1";

export const MAX_CLOCK_SKEW_MS = 60_000n;

export const SEC1_COMPRESSED_LEN = 33;
export const SEC1_COMPRESSED_EVEN = 0x02;
export const SEC1_COMPRESSED_ODD = 0x03;
export const SEC1_UNCOMPRESSED_PREFIX = 0x04;
export const SEC1_UNCOMPRESSED_LEN = 65;
export const QOS_P256_PUBLIC_LEN = SEC1_UNCOMPRESSED_LEN * 2;
export const RAW_P256_SIGNATURE_LEN = 64;
export const ED25519_SIGNATURE_LEN = 64;
export const ASN1_SEQUENCE_TAG = 0x30;

export const ADDRESS_LEN = 32;
export const NULLIFIER_SECRET_LEN = 31;
export const X25519_PUBLIC_KEY_LEN = 33;

export const AES_GCM_NONCE_LEN = 12;
export const AES_GCM_TAG_LEN = 16;
export const QOS_ENVELOPE_LEN_FIELD_LEN = 4;
/** nonce || ephemeral key || u32le sealed length || GCM tag. */
export const QOS_ENVELOPE_OVERHEAD =
  AES_GCM_NONCE_LEN + SEC1_UNCOMPRESSED_LEN + QOS_ENVELOPE_LEN_FIELD_LEN + AES_GCM_TAG_LEN;
export const SHA256_LEN = 32;
export const SHA384_LEN = 48;
export const QOS_ENCRYPTION_HMAC_MESSAGE = "qos_encryption_hmac_message";

export const MIN_MAINNET_THRESHOLD = 2;
export const MAX_AUTHORITY_THRESHOLD = 255;
export const MAX_IDENTIFIER_LEN = 128;

export const MAX_U32 = 0xffff_ffff;
export const MAX_U32_BIGINT = 0xffff_ffffn;
export const MAX_U64_BIGINT = 0xffff_ffff_ffff_ffffn;
export const MAX_SAFE_INTEGER_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);

export const DEFAULT_REQUEST_TIMEOUT_MS = 120_000;
/** Maximum signed 32-bit delay accepted by JavaScript `setTimeout`. */
export const MAX_SET_TIMEOUT_MS = 0x7fff_ffff;
