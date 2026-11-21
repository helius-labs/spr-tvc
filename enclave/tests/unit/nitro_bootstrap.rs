use openssl::{
    asn1::Asn1Time,
    cms::CMSOptions,
    hash::MessageDigest,
    stack::Stack,
    symm::Cipher,
    x509::{X509Name, X509},
};

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

fn frame(first: &[u8], second: &[u8]) -> Vec<u8> {
    [
        u16::try_from(first.len()).unwrap().to_be_bytes().as_slice(),
        first,
        second,
    ]
    .concat()
}

#[test]
fn reconstructs_the_committed_seed_for_a_new_recipient() {
    let commitments = [sha256(&[0x99; 32]), sha256(&[0x11; 32])];
    let address = [0xa5; 32];
    let open = || {
        let recipient = key();
        let first = envelope(&recipient, &[0x99; 32]);
        let second = envelope(&recipient, &[0x11; 32]);
        let seed = open_shares(&recipient, &frame(&first, &second), &commitments).unwrap();
        assert_eq!(*seed.0, [0x88; 32]);
        let keys = seed.for_address(&address);
        (
            *keys.viewing.pubkey().as_bytes(),
            keys.nullifier.pubkey().unwrap(),
        )
    };
    assert_eq!(open(), open());
}

#[test]
fn requires_two_distinct_full_shares_for_this_boot_recipient_and_commitment() {
    let recipient = key();
    let other_recipient = key();
    let commitments = [sha256(&[0x99; 32]), sha256(&[0x11; 32])];
    let first = envelope(&recipient, &[0x99; 32]);
    let second = envelope(&recipient, &[0x11; 32]);
    let replaced = envelope(&recipient, &[0x12; 32]);
    let wrong_recipient = envelope(&other_recipient, &[0x11; 32]);
    let short_secret = envelope(&recipient, &[0x11; 31]);
    let zero = envelope(&recipient, &[0; 32]);
    let oversize = vec![0; MAX_CMS_BYTES + 1];
    for (a, b) in [
        (&first[..], &[][..]),
        (&[][..], &second[..]),
        (&first, &first),
        (&first, &replaced),
        (&first, &wrong_recipient),
        (&first, &short_secret),
        (&zero, &second),
        (&first, &oversize),
        (&oversize, &second),
        (&first, &second[..second.len() - 1]),
    ] {
        assert!(open_shares(&recipient, &frame(a, b), &commitments).is_none());
    }
    assert!(open_shares(&recipient, &[0xff, 0xff], &commitments).is_none());
    assert!(open_shares(&recipient, &[0], &commitments).is_none());
    assert!(open_shares(
        &recipient,
        &frame(&first, &second),
        &[commitments[1], commitments[0]]
    )
    .is_none());
}
