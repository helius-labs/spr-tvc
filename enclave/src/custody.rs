//! Native Nitro seed identity, Shamir custody epochs, and recipient encryption.

use std::{collections::BTreeSet, io};

use openssl::{
    encrypt::Encrypter,
    hash::MessageDigest,
    pkey::{Id, PKey, Public},
    rsa::Padding,
};
use serde::{Deserialize, Serialize};
use spr_tvc_protocol::{
    digest::sha256,
    encoding::{decimal_u64, hex, jcs_serialize},
};
use vsss_rs::Gf256;
use zeroize::Zeroizing;

use crate::keys::NoteSeed;

pub(crate) const SHARE_COUNT: usize = 6;
pub(crate) const THRESHOLD: usize = 3;
const EPOCH_BYTES: usize = 8;
const SHARE_BYTES: usize = EPOCH_BYTES + 1 + 32;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Custody {
    #[serde(with = "decimal_u64")]
    pub(crate) epoch: u64,
    #[serde(with = "hex")]
    pub(crate) note_seed_commitment: [u8; 32],
    #[serde(with = "hex")]
    share_commitments: Vec<[u8; 32]>,
}

impl Custody {
    pub(crate) fn digest(&self) -> io::Result<[u8; 32]> {
        let canonical = jcs_serialize(self).map_err(io::Error::other)?;
        Ok(sha256(canonical.as_bytes()))
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.epoch == 0
            || self.note_seed_commitment == [0; 32]
            || self.share_commitments.len() != SHARE_COUNT
            || self.share_commitments.contains(&[0; 32])
            || self.share_commitments.iter().collect::<BTreeSet<_>>().len() != SHARE_COUNT
        {
            return Err(io::Error::other("invalid custody record"));
        }
        Ok(())
    }

    pub(crate) fn restore(&self, domain: &[u8; 32], shares: &[Vec<u8>]) -> Option<NoteSeed> {
        self.validate().ok()?;
        let mut verified = Zeroizing::new(Vec::with_capacity(THRESHOLD));
        let mut seen = BTreeSet::new();
        for share in shares {
            if share.len() != SHARE_BYTES || share[..EPOCH_BYTES] != self.epoch.to_be_bytes() {
                continue;
            }
            let index = usize::from(share[EPOCH_BYTES]).checked_sub(1);
            let Some(index) = index.filter(|&index| index < SHARE_COUNT) else {
                continue;
            };
            if openssl::memcmp::eq(
                &share_commitment(domain, share),
                &self.share_commitments[index],
            ) && seen.insert(index)
            {
                verified.push(share[EPOCH_BYTES..].to_vec());
            }
            if verified.len() == THRESHOLD {
                break;
            }
        }
        if verified.len() != THRESHOLD {
            return None;
        }
        let recovered = Zeroizing::new(Gf256::combine_bytes(verified.as_slice()).ok()?);
        let mut seed = Zeroizing::new([0; 32]);
        seed.copy_from_slice(&recovered);
        let seed = NoteSeed(seed);
        openssl::memcmp::eq(&note_commitment(domain, &seed), &self.note_seed_commitment)
            .then_some(seed)
    }
}

fn note_commitment(domain: &[u8; 32], seed: &NoteSeed) -> [u8; 32] {
    sha256(&Zeroizing::new(
        [
            b"SPR/native-nitro/note-seed/v1".as_slice(),
            domain,
            &seed.0[..],
        ]
        .concat(),
    ))
}

fn share_commitment(domain: &[u8; 32], share: &[u8]) -> [u8; 32] {
    sha256(&Zeroizing::new(
        [
            b"SPR/native-nitro/custody-share/v1".as_slice(),
            domain,
            share,
        ]
        .concat(),
    ))
}

fn split(epoch: u64, seed: &NoteSeed) -> io::Result<Zeroizing<Vec<Vec<u8>>>> {
    let mut shares = Zeroizing::new(
        Gf256::split_bytes(
            THRESHOLD,
            SHARE_COUNT,
            seed.0.as_slice(),
            rand_core::UnwrapErr(getrandom::SysRng),
        )
        .map_err(|_| io::Error::other("failed to split note seed"))?,
    );
    let mut encoded = Zeroizing::new(Vec::with_capacity(SHARE_COUNT));
    for (index, share) in shares.iter_mut().enumerate() {
        if share.len() != 33 || usize::from(share[0]) != index + 1 {
            return Err(io::Error::other("unexpected share identifier"));
        }
        encoded.push([epoch.to_be_bytes().as_slice(), share].concat());
    }
    Ok(encoded)
}

pub(crate) struct Recipients(Vec<PKey<Public>>);

impl Recipients {
    pub(crate) fn parse(spkis: &[Vec<u8>]) -> io::Result<Self> {
        if spkis.len() != SHARE_COUNT {
            return Err(io::Error::other("expected six recipient keys"));
        }
        let mut moduli = BTreeSet::new();
        let keys = spkis
            .iter()
            .map(|spki| {
                let key = PKey::public_key_from_der(spki).map_err(io::Error::other)?;
                if key.id() != Id::RSA || ![2048, 3072, 4096].contains(&key.bits()) {
                    return Err(io::Error::other(
                        "expected an RSA-2048, RSA-3072 or RSA-4096 recipient",
                    ));
                }
                let rsa = key.rsa().map_err(io::Error::other)?;
                if !moduli.insert(rsa.n().to_vec())
                    || key.public_key_to_der().map_err(io::Error::other)? != *spki
                {
                    return Err(io::Error::other(
                        "expected distinct canonical recipient keys",
                    ));
                }
                Ok(key)
            })
            .collect::<io::Result<_>>()?;
        Ok(Self(keys))
    }

    pub(crate) fn issue(
        &self,
        domain: &[u8; 32],
        epoch: u64,
        seed: &NoteSeed,
    ) -> io::Result<(Custody, Vec<CustodianPackage>)> {
        let shares = split(epoch, seed)?;
        let custody = Custody {
            epoch,
            note_seed_commitment: note_commitment(domain, seed),
            share_commitments: shares
                .iter()
                .map(|share| share_commitment(domain, share))
                .collect(),
        };
        custody.validate()?;
        let packages = self
            .0
            .iter()
            .zip(shares.iter())
            .map(|(key, share)| {
                let mut wrapper = Encrypter::new(key)?;
                wrapper.set_rsa_padding(Padding::PKCS1_OAEP)?;
                wrapper.set_rsa_oaep_md(MessageDigest::sha256())?;
                wrapper.set_rsa_mgf1_md(MessageDigest::sha256())?;
                let mut ciphertext = vec![0; wrapper.encrypt_len(share)?];
                let len = wrapper.encrypt(share, &mut ciphertext)?;
                ciphertext.truncate(len);
                Ok::<_, openssl::error::ErrorStack>(CustodianPackage {
                    recipient_sha256: sha256(&key.public_key_to_der()?),
                    ciphertext,
                })
            })
            .collect::<Result<_, _>>()
            .map_err(io::Error::other)?;
        Ok((custody, packages))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CustodianPackage {
    #[serde(with = "hex")]
    recipient_sha256: [u8; 32],
    #[serde(with = "hex")]
    ciphertext: Vec<u8>,
}

#[cfg(test)]
#[path = "../tests/unit/nitro_custody.rs"]
pub(crate) mod tests;
