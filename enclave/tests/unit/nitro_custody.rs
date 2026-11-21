use openssl::{encrypt::Decrypter, pkey::Private, rsa::Rsa};

use super::*;

#[test]
fn hashes_the_canonical_custody_record_for_release_attestation() {
    let custody = Custody {
        epoch: 7,
        note_seed_commitment: [0x11; 32],
        share_commitments: (1..=6).map(|byte| [byte; 32]).collect(),
    };
    assert_eq!(
        spr_tvc_protocol::encoding::encode_lower_hex(&custody.digest().unwrap()),
        "e4e5edfe00b00ffb74d4acd601ffebb90df7f6d94f23e0ee659eaf78cac5ee3e"
    );
}

pub(crate) const DOMAIN: [u8; 32] = [0xab; 32];

pub(crate) fn fixture(epoch: u64, seed: &NoteSeed) -> (Custody, Zeroizing<Vec<Vec<u8>>>) {
    let shares = split(epoch, seed).unwrap();
    let custody = Custody {
        epoch,
        note_seed_commitment: note_commitment(&DOMAIN, seed),
        share_commitments: shares
            .iter()
            .map(|share| share_commitment(&DOMAIN, share))
            .collect(),
    };
    (custody, shares)
}

#[test]
fn every_distinct_three_restore_the_seed() {
    let seed = NoteSeed(Zeroizing::new([0x88; 32]));
    let (custody, shares) = fixture(1, &seed);
    let mut tested = 0;
    for first in 0..SHARE_COUNT {
        for second in first + 1..SHARE_COUNT {
            for third in second + 1..SHARE_COUNT {
                let available = Zeroizing::new(vec![
                    shares[first].clone(),
                    shares[second].clone(),
                    shares[third].clone(),
                ]);
                let restored = custody.restore(&DOMAIN, &available).unwrap();
                assert_eq!(*restored.0, *seed.0);
                tested += 1;
            }
        }
    }
    assert_eq!(tested, 20);
}

#[test]
fn rejects_insufficient_duplicate_foreign_and_wrong_seed_shares() {
    let seed = NoteSeed(Zeroizing::new([0x88; 32]));
    let (custody, shares) = fixture(1, &seed);
    let (_, next) = fixture(2, &seed);
    for available in [
        Zeroizing::new(vec![]),
        Zeroizing::new(vec![shares[0].clone()]),
        Zeroizing::new(shares[..2].to_vec()),
        Zeroizing::new(vec![
            shares[0].clone(),
            shares[0].clone(),
            shares[1].clone(),
        ]),
        Zeroizing::new(vec![shares[0].clone(), shares[1].clone(), next[2].clone()]),
    ] {
        assert!(custody.restore(&DOMAIN, &available).is_none());
    }
    let mut invalid = Zeroizing::new(shares[..3].to_vec());
    invalid[2][SHARE_BYTES - 1] ^= 1;
    assert!(custody.restore(&DOMAIN, &invalid).is_none());
    assert!(custody.restore(&[0xcc; 32], &shares).is_none());
    let mut wrong_seed = custody.clone();
    wrong_seed.note_seed_commitment = [0x66; 32];
    assert!(wrong_seed.restore(&DOMAIN, &shares).is_none());

    let available = Zeroizing::new(vec![
        vec![0; SHARE_BYTES],
        shares[0].clone(),
        next[1].clone(),
        shares[2].clone(),
        shares[5].clone(),
    ]);
    assert_eq!(*custody.restore(&DOMAIN, &available).unwrap().0, *seed.0);
}

#[test]
fn rejects_mixing_shares_from_two_ceremonies_for_the_same_epoch() {
    let seed = NoteSeed(Zeroizing::new([0x88; 32]));
    let (canonical, shares) = fixture(2, &seed);
    let (competing, other_shares) = fixture(2, &seed);
    assert_eq!(
        canonical.note_seed_commitment,
        competing.note_seed_commitment
    );
    let mixed = Zeroizing::new(vec![
        shares[0].clone(),
        shares[1].clone(),
        other_shares[2].clone(),
    ]);
    assert!(canonical.restore(&DOMAIN, &mixed).is_none());
    assert!(competing.restore(&DOMAIN, &mixed).is_none());
}

fn keys() -> Vec<PKey<Private>> {
    (0..SHARE_COUNT)
        .map(|_| PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap())
        .collect()
}

fn import(private: &PKey<Private>, package: &CustodianPackage) -> Option<Zeroizing<Vec<u8>>> {
    let mut decoder = Decrypter::new(private).ok()?;
    decoder.set_rsa_padding(Padding::PKCS1_OAEP).ok()?;
    decoder.set_rsa_oaep_md(MessageDigest::sha256()).ok()?;
    decoder.set_rsa_mgf1_md(MessageDigest::sha256()).ok()?;
    let mut share = Zeroizing::new(vec![0; decoder.decrypt_len(&package.ciphertext).ok()?]);
    let len = decoder.decrypt(&package.ciphertext, &mut share).ok()?;
    share.truncate(len);
    Some(share)
}

#[test]
fn rotation_issues_encrypted_shares_to_new_keys_and_preserves_derived_keys() {
    let keys = keys();
    let spkis: Vec<_> = keys
        .iter()
        .map(|key| key.public_key_to_der().unwrap())
        .collect();
    let first = Recipients::parse(&spkis).unwrap();
    let seed = NoteSeed(Zeroizing::new([0x88; 32]));
    let (old, old_packages) = first.issue(&DOMAIN, 1, &seed).unwrap();
    let old_shares = Zeroizing::new(
        keys.iter()
            .zip(&old_packages)
            .map(|(key, package)| import(key, package).unwrap().to_vec())
            .collect::<Vec<_>>(),
    );
    let live = old.restore(&DOMAIN, &old_shares[..3]).unwrap();

    let replacement_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut new_spkis = spkis.clone();
    new_spkis[0] = replacement_key.public_key_to_der().unwrap();
    let next = Recipients::parse(&new_spkis).unwrap();
    let (new, new_packages) = next.issue(&DOMAIN, 2, &live).unwrap();
    assert_eq!(old.note_seed_commitment, new.note_seed_commitment);
    assert_ne!(old.share_commitments, new.share_commitments);
    assert!(import(&keys[0], &new_packages[0]).is_none());
    assert!(new.restore(&DOMAIN, &old_shares).is_none());
    let new_shares = Zeroizing::new(vec![
        import(&replacement_key, &new_packages[0]).unwrap().to_vec(),
        import(&keys[4], &new_packages[4]).unwrap().to_vec(),
        import(&keys[5], &new_packages[5]).unwrap().to_vec(),
    ]);
    let recovered = new.restore(&DOMAIN, &new_shares).unwrap();
    let old_keys = seed.for_address(&[0xab; 32]);
    let new_keys = recovered.for_address(&[0xab; 32]);
    assert_eq!(
        old_keys.viewing.pubkey().as_bytes(),
        new_keys.viewing.pubkey().as_bytes()
    );
    assert_eq!(
        old_keys.nullifier.pubkey().unwrap(),
        new_keys.nullifier.pubkey().unwrap()
    );

    new_spkis[1] = new_spkis[0].clone();
    assert!(Recipients::parse(&new_spkis).is_err());
    assert!(Recipients::parse(&spkis[..5]).is_err());
}
