//! SEC1 keys and low-S P-256 signatures.

use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::PublicKey;
use sha2::{Digest, Sha256};

use crate::constants::{RAW_P256_SIGNATURE_LEN, SEC1_UNCOMPRESSED_LEN};
use crate::error::{ErrorCode, TvcError};

pub fn parse_uncompressed_sec1(bytes: &[u8]) -> Result<PublicKey, TvcError> {
    if bytes.len() == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03) {
        return Err(TvcError::new(ErrorCode::CompressedKeyRejected));
    }
    if bytes.len() != SEC1_UNCOMPRESSED_LEN || bytes[0] != 0x04 {
        return Err(TvcError::new(ErrorCode::InvalidPublicKey));
    }
    PublicKey::from_sec1_bytes(bytes).map_err(|_| TvcError::new(ErrorCode::InvalidPublicKey))
}

pub fn public_key_uncompressed(public: &PublicKey) -> [u8; SEC1_UNCOMPRESSED_LEN] {
    let point = public.to_sec1_point(false);
    let bytes = point.as_bytes();
    let mut out = [0u8; SEC1_UNCOMPRESSED_LEN];
    out.copy_from_slice(bytes);
    out
}

fn reject_der(signature: &[u8]) -> Result<(), TvcError> {
    if signature.len() != RAW_P256_SIGNATURE_LEN {
        if !signature.is_empty() && signature[0] == 0x30 {
            return Err(TvcError::new(ErrorCode::DerSignatureRejected));
        }
        return Err(TvcError::new(ErrorCode::InvalidSignature));
    }
    Ok(())
}

/// Sign `digest` with a prehash API. The digest MUST already be SHA-256(message).
pub fn sign_p256_prehash(
    secret: &[u8; 32],
    digest: &[u8; 32],
) -> Result<[u8; RAW_P256_SIGNATURE_LEN], TvcError> {
    let signing_key =
        SigningKey::from_slice(secret).map_err(|_| TvcError::new(ErrorCode::InvalidPublicKey))?;
    let signature: Signature = signing_key
        .sign_prehash(digest)
        .map_err(|_| TvcError::new(ErrorCode::InvalidSignature))?;
    Ok(signature.normalize_s().to_bytes().into())
}

/// Verify a 64-byte raw low-S signature over an already hashed digest.
pub fn verify_p256_prehash(
    public_sec1: &[u8],
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<(), TvcError> {
    let public = parse_uncompressed_sec1(public_sec1)?;
    reject_der(signature)?;
    let signature =
        Signature::from_slice(signature).map_err(|_| TvcError::new(ErrorCode::InvalidSignature))?;
    if signature.normalize_s() != signature {
        return Err(TvcError::new(ErrorCode::HighSSignature));
    }
    VerifyingKey::from(public)
        .verify_prehash(digest, &signature)
        .map_err(|_| TvcError::new(ErrorCode::InvalidSignature))
}

/// Hash-internally APIs receive the raw domain-separated message, not a digest.
pub fn sign_p256_message(
    secret: &[u8; 32],
    message: &[u8],
) -> Result<[u8; RAW_P256_SIGNATURE_LEN], TvcError> {
    let digest: [u8; 32] = Sha256::digest(message).into();
    sign_p256_prehash(secret, &digest)
}

pub fn verify_p256_message(
    public_sec1: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), TvcError> {
    let digest: [u8; 32] = Sha256::digest(message).into();
    verify_p256_prehash(public_sec1, &digest, signature)
}
