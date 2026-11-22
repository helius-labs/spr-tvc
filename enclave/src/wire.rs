use crate::request::Failure;
use zeroize::Zeroizing;

#[cfg(any(feature = "qos-runtime", feature = "local-dev", test))]
use qos_p256::{encrypt::P256EncryptPublic, P256Pair};

#[cfg(all(feature = "native-nitro", target_os = "linux"))]
use crate::native_crypto::{NativePair, NativePeer};

pub(crate) enum KeyPair {
    #[cfg(any(feature = "qos-runtime", feature = "local-dev", test))]
    Qos(P256Pair),
    #[cfg(all(feature = "native-nitro", target_os = "linux"))]
    Native(NativePair),
}

pub(crate) enum ResponseKey {
    #[cfg(any(feature = "qos-runtime", feature = "local-dev", test))]
    Qos(P256EncryptPublic),
    #[cfg(all(feature = "native-nitro", target_os = "linux"))]
    Native(NativePeer),
}

impl KeyPair {
    pub(crate) fn public_bytes(&self) -> Vec<u8> {
        match self {
            #[cfg(any(feature = "qos-runtime", feature = "local-dev", test))]
            Self::Qos(pair) => pair.public_key().to_bytes(),
            #[cfg(all(feature = "native-nitro", target_os = "linux"))]
            Self::Native(pair) => pair.public.to_vec(),
        }
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Failure> {
        match self {
            #[cfg(any(feature = "qos-runtime", feature = "local-dev", test))]
            Self::Qos(pair) => pair.sign(message).map_err(|_| Failure::Unavailable),
            #[cfg(all(feature = "native-nitro", target_os = "linux"))]
            Self::Native(pair) => pair.sign(message).map_err(|_| Failure::Unavailable),
        }
    }

    pub(crate) fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Failure> {
        match self {
            #[cfg(any(feature = "qos-runtime", feature = "local-dev", test))]
            Self::Qos(pair) => pair.decrypt(ciphertext).map_err(|_| Failure::Invalid),
            #[cfg(all(feature = "native-nitro", target_os = "linux"))]
            Self::Native(pair) => pair.decrypt(ciphertext).ok_or(Failure::Invalid),
        }
    }

    pub(crate) fn response_key(&self, bytes: &[u8]) -> Result<ResponseKey, Failure> {
        match self {
            #[cfg(any(feature = "qos-runtime", feature = "local-dev", test))]
            Self::Qos(_) => P256EncryptPublic::from_bytes(bytes)
                .map(ResponseKey::Qos)
                .map_err(|_| Failure::Invalid),
            #[cfg(all(feature = "native-nitro", target_os = "linux"))]
            Self::Native(_) => NativePeer::parse(bytes)
                .map(ResponseKey::Native)
                .ok_or(Failure::Invalid),
        }
    }
}

impl ResponseKey {
    pub(crate) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Failure> {
        match self {
            #[cfg(any(feature = "qos-runtime", feature = "local-dev", test))]
            Self::Qos(peer) => peer.encrypt(plaintext).map_err(|_| Failure::Unavailable),
            #[cfg(all(feature = "native-nitro", target_os = "linux"))]
            Self::Native(peer) => peer.encrypt(plaintext).map_err(|_| Failure::Unavailable),
        }
    }
}
