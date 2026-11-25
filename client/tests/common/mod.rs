use std::sync::Mutex;

use ed25519_dalek::Signer;
use qos_p256::encrypt::P256EncryptPair;
use serde::Deserialize;
use spr_keypair::{random_salt, ShieldedAddress, ViewingKey};
use spr_tvc_protocol::encoding::parse_strict_json;
use spr_tvc_protocol::types::EncryptedResponse;
use spr_tvc_protocol::DecryptLabel;

use spr_tvc_client::{ClientError, Note, OwnerSigner, Transport};

pub struct Key(ed25519_dalek::SigningKey);

impl Key {
    pub fn from_seed(seed: u8) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }
}

impl OwnerSigner for Key {
    fn pubkey(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    fn sign_offchain(&self, message: &[u8]) -> Result<[u8; 64], ClientError> {
        Ok(self.0.sign(message).to_bytes())
    }
}

pub fn one_note(address: &ShieldedAddress) -> (Note, Vec<u8>) {
    let sender = ViewingKey::new();
    let salt = random_salt();
    let plaintext = b"ten usdc".to_vec();
    let ciphertext = sender
        .encrypt_slot(&address.viewing_pubkey, &plaintext, salt, 0)
        .expect("encrypt one note");
    let note = Note {
        ciphertext,
        ephemeral_viewing_public_key: *sender.pubkey().as_bytes(),
        salt: salt.to_vec(),
        slot_index: 0,
        label: DecryptLabel::Transfer,
    };
    (note, plaintext)
}

#[derive(Clone)]
pub struct Post {
    pub url: String,
    pub body: String,
    pub response: Vec<u8>,
}

pub struct Tape<T> {
    inner: T,
    posts: Mutex<Vec<Post>>,
}

impl<T> Tape<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            posts: Mutex::new(Vec::new()),
        }
    }

    pub fn posts(&self) -> Vec<Post> {
        self.posts.lock().expect("tape").clone()
    }
}

impl<T: Transport> Transport for &Tape<T> {
    fn get(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>, ClientError> {
        Transport::get(*self, url, max_bytes)
    }

    fn post(&self, url: &str, body: &str, max_bytes: usize) -> Result<Vec<u8>, ClientError> {
        Transport::post(*self, url, body, max_bytes)
    }

    fn post_with_api_key(
        &self,
        url: &str,
        api_key: &str,
        body: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ClientError> {
        Transport::post_with_api_key(*self, url, api_key, body, max_bytes)
    }
}

impl<T: Transport> Transport for Tape<T> {
    fn get(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>, ClientError> {
        self.inner.get(url, max_bytes)
    }

    fn post(&self, url: &str, body: &str, max_bytes: usize) -> Result<Vec<u8>, ClientError> {
        let response = self.inner.post(url, body, max_bytes)?;
        self.record(url, body, &response);
        Ok(response)
    }

    fn post_with_api_key(
        &self,
        url: &str,
        api_key: &str,
        body: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ClientError> {
        let response = self
            .inner
            .post_with_api_key(url, api_key, body, max_bytes)?;
        self.record(url, body, &response);
        Ok(response)
    }
}

impl<T> Tape<T> {
    fn record(&self, url: &str, body: &str, response: &[u8]) {
        self.posts.lock().expect("tape").push(Post {
            url: url.to_owned(),
            body: body.to_owned(),
            response: response.to_vec(),
        });
    }
}

/// Sends the captured request again. The enclave seals each reply with a fresh nonce, so the
/// bytes differ, and a key that was not in the request cannot open either reply.
pub fn replay<T: Transport>(tape: &Tape<T>, post: &Post, api_key: Option<&str>) {
    let again = match api_key {
        Some(api_key) => tape
            .inner
            .post_with_api_key(&post.url, api_key, &post.body, 16 * 1024 * 1024)
            .expect("replay"),
        None => tape
            .inner
            .post(&post.url, &post.body, 16 * 1024 * 1024)
            .expect("replay"),
    };
    let first = encrypted_response(&post.response);
    let second = encrypted_response(&again);
    assert_eq!(first.request_id, second.request_id);
    let stranger = P256EncryptPair::generate();
    assert!(stranger.decrypt(&first.encrypted_result).is_err());
    assert!(stranger.decrypt(&second.encrypted_result).is_err());
}

fn encrypted_response(body: &[u8]) -> EncryptedResponse {
    let text = std::str::from_utf8(body).expect("utf-8 response");
    if let Ok(response) = parse_strict_json::<EncryptedResponse>(text) {
        return response;
    }
    let wrapped: OperationAnswer = parse_strict_json(text).expect("operation answer");
    wrapped.response
}

#[derive(Deserialize)]
struct OperationAnswer {
    response: EncryptedResponse,
}
