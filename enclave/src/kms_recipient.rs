//! Accept the CMS suite used by KMS CiphertextForRecipient.

use cms::{
    content_info::{CmsVersion, ContentInfo},
    enveloped_data::{EnvelopedData, RecipientIdentifier, RecipientInfo},
};
use openssl::{
    cms::CmsContentInfo,
    encrypt::Decrypter,
    hash::MessageDigest,
    pkey::{PKeyRef, Private},
    rsa::Padding,
    symm::{Cipher, Crypter, Mode},
};
use pkcs1::{
    der::{
        asn1::{AnyRef, OctetStringRef},
        Decode,
    },
    ObjectIdentifier, RsaOaepParams,
};
use zeroize::Zeroizing;

use crate::custody::SHARE_BYTES;

pub(crate) const MAX_CMS_BYTES: usize = 6_144;
const RSA2048_BYTES: usize = 256;
const AES_BLOCK_BYTES: usize = 16;
const CONTENT_KEY_BYTES: usize = 32;
const ENCRYPTED_SHARE_BYTES: usize = (SHARE_BYTES / AES_BLOCK_BYTES + 1) * AES_BLOCK_BYTES;
const ENVELOPED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");
const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const RSA_OAEP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.7");
const MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
const P_SPECIFIED: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.9");
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const AES256_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");

pub(crate) fn open_share(key: &PKeyRef<Private>, envelope: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if envelope.is_empty() || envelope.len() > MAX_CMS_BYTES {
        return None;
    }
    // KMS emits BER. Normalize it before reading the algorithms and ciphertext.
    let cms = CmsContentInfo::from_der(envelope).ok()?;
    let envelope = parse_kms_ciphertext(&cms.to_der().ok()?)?;

    let mut rsa = Decrypter::new(key).ok()?;
    rsa.set_rsa_padding(Padding::PKCS1_OAEP).ok()?;
    rsa.set_rsa_oaep_md(MessageDigest::sha256()).ok()?;
    rsa.set_rsa_mgf1_md(MessageDigest::sha256()).ok()?;
    let mut content_key = Zeroizing::new([0; RSA2048_BYTES]);
    let count = rsa
        .decrypt(&envelope.encrypted_key, content_key.as_mut())
        .ok()?;
    if count != CONTENT_KEY_BYTES {
        return None;
    }
    let cipher = Cipher::aes_256_cbc();
    let mut decrypt = Crypter::new(
        cipher,
        Mode::Decrypt,
        &content_key[..CONTENT_KEY_BYTES],
        Some(&envelope.iv),
    )
    .ok()?;
    drop(content_key);
    let mut share = Zeroizing::new(vec![0; ENCRYPTED_SHARE_BYTES + AES_BLOCK_BYTES]);
    let count = decrypt.update(&envelope.content, &mut share).ok()?;
    let rest = decrypt.finalize(&mut share[count..]).ok()?;
    if count + rest != SHARE_BYTES {
        return None;
    }
    share.truncate(SHARE_BYTES);
    Some(share)
}

struct RecipientCiphertext {
    encrypted_key: [u8; RSA2048_BYTES],
    iv: [u8; AES_BLOCK_BYTES],
    content: [u8; ENCRYPTED_SHARE_BYTES],
}

fn parse_kms_ciphertext(der: &[u8]) -> Option<RecipientCiphertext> {
    let info = ContentInfo::from_der(der).ok()?;
    if info.content_type != ENVELOPED_DATA {
        return None;
    }
    let envelope: EnvelopedData = info.content.decode_as().ok()?;
    let [RecipientInfo::Ktri(recipient)] = envelope.recip_infos.0.as_slice() else {
        return None;
    };
    let content = envelope.encrypted_content;
    if envelope.version != CmsVersion::V2
        || envelope.originator_info.is_some()
        || envelope.unprotected_attrs.is_some()
        || recipient.version != CmsVersion::V2
        || !matches!(recipient.rid, RecipientIdentifier::SubjectKeyIdentifier(_))
        || recipient.key_enc_alg.oid != RSA_OAEP
        || content.content_type != DATA
        || content.content_enc_alg.oid != AES256_CBC
    {
        return None;
    }
    let params: RsaOaepParams = recipient
        .key_enc_alg
        .parameters
        .as_ref()?
        .decode_as()
        .ok()?;
    let mask_hash = params.mask_gen.parameters?;
    let label: OctetStringRef = params.p_source.parameters?.decode_as().ok()?;
    if params.hash.oid != SHA256
        || params
            .hash
            .parameters
            .is_some_and(|value| value != AnyRef::NULL)
        || params.mask_gen.oid != MGF1
        || mask_hash.oid != SHA256
        || mask_hash
            .parameters
            .is_some_and(|value| value != AnyRef::NULL)
        || params.p_source.oid != P_SPECIFIED
        || !label.as_bytes().is_empty()
    {
        return None;
    }
    let iv: OctetStringRef = content
        .content_enc_alg
        .parameters
        .as_ref()?
        .decode_as()
        .ok()?;
    Some(RecipientCiphertext {
        encrypted_key: recipient.enc_key.as_bytes().try_into().ok()?,
        iv: iv.as_bytes().try_into().ok()?,
        content: content.encrypted_content?.as_bytes().try_into().ok()?,
    })
}

#[cfg(test)]
#[path = "../tests/unit/nitro_kms_recipient.rs"]
pub(crate) mod tests;
