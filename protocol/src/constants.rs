//! Wire versions, domains, and limits.

pub const API_VERSION: u8 = 2;
pub const TVC_APP_PROOF_SCHEME: &str = "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256";
pub const TVC_QOS_PING_PROOF_TYPE: &str = "spr.tvc.qos_ping.v2";
pub const EXPECTED_TURNKEY_TRUST_ROOT_ID: &str = "aws-nitro-root-g1";
pub const RESULT_DIGEST_DOMAIN: &[u8] = b"SPR_TVC_RESULT_V2";
pub const RELEASE_POLICY_DOMAIN: &[u8] = b"SPR_TVC_RELEASE_POLICY_V2";
pub const MAX_ENCRYPTED_REQUEST_BYTES: u64 = 262_144;
pub const MAX_ENCRYPTED_RESPONSE_BYTES: u64 = 262_144;
pub const MAX_ITEMS_PER_BATCH: u64 = 256;
pub const SEC1_UNCOMPRESSED_LEN: usize = 65;
pub const QOS_P256_PUBLIC_LEN: usize = 130;
pub const RAW_P256_SIGNATURE_LEN: usize = 64;
pub const AES_GCM_NONCE_LEN: usize = 12;
pub const AES_GCM_TAG_LEN: usize = 16;
pub const QOS_ENCRYPTION_HMAC_MESSAGE: &[u8] = b"qos_encryption_hmac_message";
