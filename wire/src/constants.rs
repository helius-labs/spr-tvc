//! Wire versions, domains, and limits.

pub const API_VERSION: u8 = 1;
pub const TVC_APP_PROOF_SCHEME: &str = "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256";
pub const TVC_QOS_PING_PROOF_TYPE: &str = "spr.tvc.qos_ping.v1";
pub const EXPECTED_TURNKEY_TRUST_ROOT_ID: &str = "aws-nitro-root-g1";
pub const RESULT_DIGEST_DOMAIN: &[u8] = b"SPR_TVC_RESULT_V1";
pub const RELEASE_POLICY_DOMAIN: &[u8] = b"SPR_TVC_RELEASE_POLICY_V1";

pub const SHA256_LEN: usize = 32;
pub const SHA384_LEN: usize = 48;
pub const AES_GCM_NONCE_LEN: usize = 12;
pub const AES_GCM_TAG_LEN: usize = 16;
pub const QOS_ENVELOPE_LEN_FIELD_LEN: usize = 4;

pub const SEC1_COMPRESSED_LEN: usize = 33;
pub const SEC1_COMPRESSED_EVEN: u8 = 0x02;
pub const SEC1_COMPRESSED_ODD: u8 = 0x03;
pub const SEC1_UNCOMPRESSED_PREFIX: u8 = 0x04;
pub const SEC1_UNCOMPRESSED_LEN: usize = 65;
pub const QOS_P256_PUBLIC_LEN: usize = SEC1_UNCOMPRESSED_LEN * 2;
pub const RAW_P256_SIGNATURE_LEN: usize = 64;
pub const ASN1_SEQUENCE_TAG: u8 = 0x30;

/// nonce || ephemeral key || u32le sealed length || GCM tag.
/// The sealed length counts ciphertext and tag, and the ciphertext is the same
/// length as the plaintext, so a QOS frame is `plaintext + QOS_ENVELOPE_OVERHEAD`.
pub const QOS_ENVELOPE_OVERHEAD: usize =
    AES_GCM_NONCE_LEN + SEC1_UNCOMPRESSED_LEN + QOS_ENVELOPE_LEN_FIELD_LEN + AES_GCM_TAG_LEN;

/// Maximum clock skew tolerated when validating attestation freshness.
pub const MAX_CLOCK_SKEW_MS: u64 = 60_000;

/// IEEE 754 `Number.MAX_SAFE_INTEGER` (2^53 - 1) shared across Rust and TypeScript wire bounds.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Maximum length of pinned namespace and manifest-set member identifiers.
pub const MAX_IDENTIFIER_LEN: usize = 128;

/// Minimum threshold required for mainnet release authorities and manifest/share quorums.
pub const MIN_MAINNET_THRESHOLD: u8 = 2;

/// One SPR indexer page (`PAGE_LIMIT` in the Zolana SDK). One owner signature
/// covers this many notes. The body cap is 10 MiB, not this count.
pub const NOTES_PER_SIGNATURE: usize = 1_000;

/// Empty confidential recipient ciphertext. Zolana's transfer layout.
pub const EMPTY_RECIPIENT_CIPHERTEXT_LEN: usize = 50;

/// Encrypted HTTP body the service will read, and the encrypted-result ceiling.
/// Same 10 MiB body cap as Photon and the SPR SDK indexer client. An empty
/// indexer page measures 675,396 bytes and fits inside it.
pub const MAX_ENCRYPTED_REQUEST_BYTES: u64 = 10 * 1024 * 1024;
pub const MAX_ENCRYPTED_RESPONSE_BYTES: u64 = MAX_ENCRYPTED_REQUEST_BYTES;

/// The body cap as a release policy records it. The policy field is a `u32`.
pub const MAX_ENCRYPTED_POLICY_BYTES: u32 = {
    assert!(MAX_ENCRYPTED_REQUEST_BYTES == MAX_ENCRYPTED_RESPONSE_BYTES);
    assert!(MAX_ENCRYPTED_REQUEST_BYTES <= u32::MAX as u64);
    MAX_ENCRYPTED_REQUEST_BYTES as u32
};
