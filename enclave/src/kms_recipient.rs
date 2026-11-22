//! Accept the CMS suite used by KMS CiphertextForRecipient.

use cms::{
    content_info::{CmsVersion, ContentInfo},
    enveloped_data::{EnvelopedData, RecipientIdentifier, RecipientInfo},
};
use openssl::{
    cms::CmsContentInfo,
    pkey::{PKeyRef, Private},
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
    // KMS emits BER. Normalize and inspect the parsed object before OpenSSL uses it.
    let cms = CmsContentInfo::from_der(envelope).ok()?;
    require_kms_suite(&cms.to_der().ok()?)?;
    let share = Zeroizing::new(cms.decrypt_without_cert_check(key).ok()?);
    (share.len() == SHARE_BYTES).then_some(share)
}

fn require_kms_suite(der: &[u8]) -> Option<()> {
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
        || recipient.enc_key.as_bytes().len() != RSA2048_BYTES
        || recipient.key_enc_alg.oid != RSA_OAEP
        || content.content_type != DATA
        || content.content_enc_alg.oid != AES256_CBC
        || content.encrypted_content?.as_bytes().len() != ENCRYPTED_SHARE_BYTES
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
    let iv: OctetStringRef = content
        .content_enc_alg
        .parameters
        .as_ref()?
        .decode_as()
        .ok()?;
    (params.hash.oid == SHA256
        && params
            .hash
            .parameters
            .is_none_or(|value| value == AnyRef::NULL)
        && params.mask_gen.oid == MGF1
        && mask_hash.oid == SHA256
        && mask_hash
            .parameters
            .is_none_or(|value| value == AnyRef::NULL)
        && params.p_source.oid == P_SPECIFIED
        && label.as_bytes().is_empty()
        && iv.as_bytes().len() == AES_BLOCK_BYTES)
        .then_some(())
}

#[cfg(test)]
#[path = "../tests/unit/nitro_kms_recipient.rs"]
pub(crate) mod tests;
