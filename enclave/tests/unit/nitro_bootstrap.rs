use openssl::{
    asn1::Asn1Time,
    cms::CMSOptions,
    hash::MessageDigest,
    stack::Stack,
    symm::Cipher,
    x509::{X509Name, X509},
};

use crate::custody::tests::{fixture, DOMAIN};

use super::*;

fn key() -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
}

fn envelope(key: &PKey<Private>, share: &[u8]) -> Vec<u8> {
    let mut cert = X509::builder().unwrap();
    let name = X509Name::builder().unwrap().build();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.sign(key, MessageDigest::sha256()).unwrap();
    let mut recipients = Stack::new().unwrap();
    recipients.push(cert.build()).unwrap();
    CmsContentInfo::encrypt(
        &recipients,
        share,
        Cipher::aes_256_cbc(),
        CMSOptions::BINARY,
    )
    .unwrap()
    .to_der()
    .unwrap()
}

fn frame(envelopes: &[&[u8]]) -> Vec<u8> {
    let mut frame = Vec::new();
    for envelope in envelopes {
        frame.extend(u16::try_from(envelope.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(envelope);
    }
    frame
}

#[test]
fn bootstrap_requires_three_distinct_valid_shares_for_this_boot_recipient() {
    let seed = NoteSeed(Zeroizing::new([0x88; 32]));
    let (custody, shares) = fixture(1, &seed);
    let recipient = key();
    let wrong_recipient = key();
    let [first, second, third] = [0, 2, 5].map(|index| envelope(&recipient, &shares[index]));
    let wrong = envelope(&wrong_recipient, &shares[5]);
    let short = envelope(&recipient, &[0; 32]);
    let large = vec![0; MAX_CMS_BYTES + 1];
    for envelopes in [
        vec![first.as_slice(), &second],
        vec![&first, &first, &second],
        vec![&first, &second, &wrong],
        vec![&first, &second, &short],
        vec![&first, &second, &large],
        vec![&first, &second, &third[..third.len() - 1]],
        vec![&first, &second, &third, &third, &third, &third, &third],
    ] {
        let bytes = frame(&envelopes);
        assert!(open_shares(&recipient, &bytes, &DOMAIN, &custody).is_none());
    }
    assert!(open_shares(&recipient, &[0], &DOMAIN, &custody).is_none());
    assert!(open_shares(&recipient, &[0xff, 0xff], &DOMAIN, &custody).is_none());
    let bytes = frame(&[&first, &second, &wrong, &third]);
    assert_eq!(
        *open_shares(&recipient, &bytes, &DOMAIN, &custody)
            .unwrap()
            .0,
        *seed.0
    );
}
