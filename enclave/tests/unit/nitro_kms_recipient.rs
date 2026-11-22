use cms::enveloped_data::{EncryptedContentInfo, KeyTransRecipientInfo};
use openssl::{
    encrypt::Encrypter,
    hash::MessageDigest,
    pkey::PKey,
    rsa::{Padding, Rsa},
    symm::{encrypt, Cipher},
};
use pkcs1::der::{
    asn1::{Any, OctetString},
    Encode, Tag,
};

use super::*;

const OAEP_SHA256: &str = concat!(
    "303c06092a864886f70d010107302f",
    "a00f300d06096086480165030402010500",
    "a11c301a06092a864886f70d010108300d06096086480165030402010500",
);

pub(crate) fn envelope(key: &PKey<Private>, share: &[u8]) -> Vec<u8> {
    seal(key, share, Padding::PKCS1_OAEP)
}

fn seal(key: &PKey<Private>, share: &[u8], padding: Padding) -> Vec<u8> {
    let cek = [0x42; 32];
    let iv = [0x13; 16];
    let mut wrap = Encrypter::new(key).unwrap();
    wrap.set_rsa_padding(padding).unwrap();
    let algorithm = if padding == Padding::PKCS1_OAEP {
        wrap.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
        wrap.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
        OAEP_SHA256
    } else {
        "300d06092a864886f70d0101010500"
    };
    let mut wrapped = vec![0; wrap.encrypt_len(&cek).unwrap()];
    let len = wrap.encrypt(&cek, &mut wrapped).unwrap();
    wrapped.truncate(len);
    let recipient = RecipientInfo::Ktri(KeyTransRecipientInfo {
        version: CmsVersion::V2,
        rid: RecipientIdentifier::SubjectKeyIdentifier(Decode::from_der(&[4, 1, 1]).unwrap()),
        key_enc_alg: Decode::from_der(&::hex::decode(algorithm).unwrap()).unwrap(),
        enc_key: OctetString::new(wrapped).unwrap(),
    });
    let content_enc_alg = [
        ::hex::decode("301d060960864801650304012a0410").unwrap(),
        iv.to_vec(),
    ]
    .concat();
    let enveloped = EnvelopedData {
        version: CmsVersion::V2,
        originator_info: None,
        recip_infos: vec![recipient].try_into().unwrap(),
        encrypted_content: EncryptedContentInfo {
            content_type: DATA,
            content_enc_alg: Decode::from_der(&content_enc_alg).unwrap(),
            encrypted_content: Some(
                OctetString::new(encrypt(Cipher::aes_256_cbc(), &cek, Some(&iv), share).unwrap())
                    .unwrap(),
            ),
        },
        unprotected_attrs: None,
    };
    ContentInfo {
        content_type: ENVELOPED_DATA,
        content: Any::encode_from(&enveloped).unwrap(),
    }
    .to_der()
    .unwrap()
}

#[test]
fn rejects_other_rsa_padding_and_wrong_plaintext_size_before_admitting_shares() {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let share = [0x22; SHARE_BYTES];
    let envelope = envelope(&key, &share);
    assert_eq!(open_share(&key, &envelope).unwrap().as_slice(), share);
    let other_padding = seal(&key, &share, Padding::PKCS1);
    assert_eq!(
        CmsContentInfo::from_der(&other_padding)
            .unwrap()
            .decrypt_without_cert_check(&key)
            .unwrap(),
        share,
    );
    assert!(open_share(&key, &other_padding).is_none());
    // AES-CBC padding still yields the expected ciphertext length for 40 bytes.
    assert!(open_share(&key, &seal(&key, &share[..40], Padding::PKCS1_OAEP)).is_none());
}

#[test]
fn accepts_aws_nitro_sdk_ber_at_the_algorithm_boundary() {
    // AWS Nitro Enclaves SDK for C, tests/kmstool-enclaves/cms_test.c,
    // input_ber, f2dbc3fb1ab9b4496ff8ebc077d24e5f24265923 (Apache-2.0).
    let ber = include_bytes!("../fixtures/aws-kms-recipient.ber");
    let cms = CmsContentInfo::from_der(ber).unwrap();
    assert!(require_kms_suite(&cms.to_der().unwrap()).is_some());
}

#[test]
fn independently_checks_oaep_hash_mgf_hash_and_content_cipher_oids() {
    let cms =
        CmsContentInfo::from_der(include_bytes!("../fixtures/aws-kms-recipient.ber")).unwrap();
    let encoded = cms.to_der().unwrap();
    let sha256 = SHA256.to_der().unwrap();
    let aes256_cbc = AES256_CBC.to_der().unwrap();
    let mut hashes = encoded.windows(sha256.len());
    let oaep = hashes.clone().position(|value| value == sha256).unwrap();
    let mgf = hashes.rposition(|value| value == sha256).unwrap();
    assert!(oaep < mgf);
    let content = encoded
        .windows(aes256_cbc.len())
        .position(|value| value == aes256_cbc)
        .unwrap();
    for (offset, oid) in [(oaep, &sha256), (mgf, &sha256), (content, &aes256_cbc)] {
        let mut unsupported = encoded.clone();
        unsupported[offset + oid.len() - 1] ^= 1;
        assert!(require_kms_suite(&unsupported).is_none());
    }
}

#[test]
fn rejects_nonempty_oaep_labels_and_multiple_recipients() {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut info = ContentInfo::from_der(&envelope(&key, &[0x22; SHARE_BYTES])).unwrap();
    let mut data: EnvelopedData = info.content.decode_as().unwrap();
    let RecipientInfo::Ktri(recipient) = data.recip_infos.0.as_slice()[0].clone() else {
        panic!("expected one key transport recipient");
    };
    let mut with_label = recipient.clone();
    let mut params: RsaOaepParams = recipient
        .key_enc_alg
        .parameters
        .as_ref()
        .unwrap()
        .decode_as()
        .unwrap();
    params.p_source.parameters = Some(AnyRef::new(Tag::OctetString, &[1]).unwrap());
    with_label.key_enc_alg.parameters = Some(Any::encode_from(&params).unwrap());

    let mut second = recipient.clone();
    second.rid = RecipientIdentifier::SubjectKeyIdentifier(Decode::from_der(&[4, 1, 2]).unwrap());
    for recipients in [vec![with_label], vec![recipient, second]] {
        data.recip_infos = recipients
            .into_iter()
            .map(RecipientInfo::Ktri)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        info.content = Any::encode_from(&data).unwrap();
        assert!(require_kms_suite(&info.to_der().unwrap()).is_none());
    }
}
