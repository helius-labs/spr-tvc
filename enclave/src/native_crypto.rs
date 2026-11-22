//! The SPR P-256 envelope, implemented with OpenSSL primitives.
use openssl::{
    bn::BigNumContext,
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    ecdsa::EcdsaSig,
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private, Public},
    rand::rand_bytes,
    sign::Signer,
    symm::{encrypt_aead, Cipher, Crypter, Mode},
};
use spr_tvc_protocol::digest::sha256;
use zeroize::Zeroizing;

const POINT: usize = 65;
const NONCE: usize = 12;
const TAG: usize = 16;

pub(crate) struct NativePair {
    encryption: PKey<Private>,
    signing: EcKey<Private>,
    pub(crate) public: Vec<u8>,
}

pub(crate) struct NativePeer {
    key: PKey<Public>,
    point: [u8; POINT],
}

impl NativePair {
    pub(crate) fn generate() -> Result<Self, ErrorStack> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut ctx = BigNumContext::new()?;
        let encryption = EcKey::generate(&group)?;
        let signing = EcKey::generate(&group)?;
        let mut public = encryption.public_key().to_bytes(
            &group,
            PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )?;
        public.extend(signing.public_key().to_bytes(
            &group,
            PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )?);
        Ok(Self {
            encryption: PKey::from_ec_key(encryption)?,
            signing,
            public,
        })
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let signature = EcdsaSig::sign(&sha256(message), &self.signing)?;
        let mut bytes = signature.r().to_vec_padded(32)?;
        bytes.extend(signature.s().to_vec_padded(32)?);
        Ok(bytes)
    }

    pub(crate) fn decrypt(&self, frame: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let (nonce, frame) = frame.split_first_chunk::<NONCE>()?;
        let (sender, frame) = frame.split_first_chunk::<POINT>()?;
        let (length, sealed) = frame.split_first_chunk::<4>()?;
        if sealed.len() != u32::from_le_bytes(*length) as usize {
            return None;
        }
        let (ciphertext, tag) = sealed.split_last_chunk::<TAG>()?;
        let peer = NativePeer::parse(sender)?;
        let receiver = &self.public[..POINT];
        let key = cipher_key(&self.encryption, &peer.key, sender, receiver).ok()?;
        let cipher = Cipher::aes_256_gcm();
        let mut decrypt = Crypter::new(cipher, Mode::Decrypt, &key[..32], Some(nonce)).ok()?;
        decrypt.aad_update(&aad(sender, receiver)).ok()?;
        // OpenSSL writes plaintext in update and authenticates it in finalize.
        let mut plaintext = Zeroizing::new(vec![0; ciphertext.len() + cipher.block_size()]);
        let count = decrypt.update(ciphertext, &mut plaintext).ok()?;
        decrypt.set_tag(tag).ok()?;
        let rest = decrypt.finalize(&mut plaintext[count..]).ok()?;
        plaintext.truncate(count + rest);
        Some(plaintext)
    }
}

impl NativePeer {
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        let point: [u8; POINT] = bytes.try_into().ok()?;
        if point[0] != 4 {
            return None;
        }
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).ok()?;
        let mut ctx = BigNumContext::new().ok()?;
        let parsed = EcPoint::from_bytes(&group, &point, &mut ctx).ok()?;
        let key = EcKey::from_public_key(&group, &parsed).ok()?;
        key.check_key().ok()?;
        Some(Self {
            key: PKey::from_ec_key(key).ok()?,
            point,
        })
    }

    pub(crate) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut ctx = BigNumContext::new()?;
        let sender = EcKey::generate(&group)?;
        let public =
            sender
                .public_key()
                .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
        let sender = PKey::from_ec_key(sender)?;
        let key = cipher_key(&sender, &self.key, &public, &self.point)?;
        let mut nonce = [0; NONCE];
        rand_bytes(&mut nonce)?;
        let mut tag = [0; TAG];
        let sealed = encrypt_aead(
            Cipher::aes_256_gcm(),
            &key[..32],
            Some(&nonce),
            &aad(&public, &self.point),
            plaintext,
            &mut tag,
        )?;
        let length = (sealed.len() + TAG) as u32;
        Ok([
            nonce.as_slice(),
            &public,
            &length.to_le_bytes(),
            &sealed,
            &tag,
        ]
        .concat())
    }
}

fn cipher_key(
    secret: &PKey<Private>,
    peer: &PKey<Public>,
    sender: &[u8],
    receiver: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ErrorStack> {
    let mut agreement = Deriver::new(secret)?;
    agreement.set_peer(peer)?;
    let shared = Zeroizing::new(agreement.derive_to_vec()?);
    let preimage = Zeroizing::new([sender, receiver, shared.as_slice()].concat());
    let hmac_key = PKey::hmac(&preimage)?;
    let mut hmac = Signer::new(MessageDigest::sha512(), &hmac_key)?;
    hmac.update(b"qos_encryption_hmac_message")?;
    Ok(Zeroizing::new(hmac.sign_to_vec()?))
}

fn aad(sender: &[u8], receiver: &[u8]) -> Vec<u8> {
    [sender, &[POINT as u8], receiver, &[POINT as u8]].concat()
}

#[cfg(test)]
#[path = "../tests/unit/nitro_wire.rs"]
mod tests;
