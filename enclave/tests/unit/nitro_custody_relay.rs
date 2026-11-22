use openssl::{
    encrypt::Decrypter,
    hash::MessageDigest,
    rsa::{Padding, Rsa},
};
use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

use crate::nitro::tests::envelope;

use super::*;

const DOMAIN: [u8; 32] = [0xbb; 32];
const EPOCH: u64 = 7;

fn rsa() -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
}

struct Fixture {
    relay: Relay,
    signers: [SigningKey; 3],
    destination: PKey<Private>,
    share: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let signers = [1, 2, 3].map(|value| SigningKey::from_bytes(&[value; 32].into()).unwrap());
        let pins = signers.each_ref().map(|key| {
            key.verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .try_into()
                .unwrap()
        });
        assert!(Relay::new(rsa(), Network::Devnet, DOMAIN, EPOCH, [pins[0]; 3]).is_err());
        let relay = Relay::new(rsa(), Network::Devnet, DOMAIN, EPOCH, pins).unwrap();
        let share = [EPOCH.to_be_bytes().as_slice(), &[4], &[0x6c; 32]].concat();
        Self {
            relay,
            signers,
            destination: rsa(),
            share,
        }
    }

    fn request(&self) -> Request {
        let statement = Statement {
            network: Network::Devnet,
            security_domain_id: DOMAIN,
            custody_epoch: EPOCH,
            slot: 4,
            share_commitment: sha256(
                &[
                    b"SPR/native-nitro/custody-share/v1".as_slice(),
                    &DOMAIN,
                    &self.share,
                ]
                .concat(),
            ),
            relay_key_id: sha256(&self.relay.public_key().unwrap()),
            target_digest: [0x37; 32],
            destination_public_key: self.destination.public_key_to_der().unwrap(),
        };
        let approvals = self.approve(&statement, [1, 3]);
        Request {
            statement,
            approvals,
            envelope: envelope(&self.relay.recipient, &self.share),
        }
    }

    fn approve(&self, statement: &Statement, authorities: [u8; 2]) -> [Approval; 2] {
        let digest = signing_digest(statement).unwrap();
        authorities.map(|authority| {
            let signature: Signature = self.signers[usize::from(authority - 1)]
                .sign_prehash(&digest)
                .unwrap();
            Approval {
                authority,
                signature: signature
                    .normalize_s()
                    .unwrap_or(signature)
                    .to_bytes()
                    .into(),
            }
        })
    }
}

#[test]
fn rewraps_a_committed_share_for_the_two_signers_exact_destination() {
    let fix = Fixture::new();
    let ciphertext = fix.relay.rewrap(fix.request()).unwrap();
    assert_ne!(ciphertext, fix.share);
    let mut decrypt = Decrypter::new(&fix.destination).unwrap();
    decrypt.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
    decrypt.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
    decrypt.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
    let mut plaintext = vec![0; decrypt.decrypt_len(&ciphertext).unwrap()];
    let len = decrypt.decrypt(&ciphertext, &mut plaintext).unwrap();
    assert_eq!(&plaintext[..len], fix.share);
}

#[test]
fn refuses_other_destinations_duplicate_approvals_and_another_boot() {
    let fix = Fixture::new();
    let mut request = fix.request();
    request.statement.destination_public_key = rsa().public_key_to_der().unwrap();
    assert!(fix.relay.rewrap(request).is_none());
    let mut request = fix.request();
    request.approvals = fix.approve(&request.statement, [1, 1]);
    assert!(fix.relay.rewrap(request).is_none());
    let mut request = fix.request();
    request.approvals[0].authority = 2;
    assert!(fix.relay.rewrap(request).is_none());
    let mut request = fix.request();
    request.statement.relay_key_id = [9; 32];
    request.approvals = fix.approve(&request.statement, [1, 3]);
    assert!(fix.relay.rewrap(request).is_none());
}

#[test]
fn checks_scope_and_commitment_even_after_two_approvals() {
    let fix = Fixture::new();
    for alter in [
        (|statement: &mut Statement| statement.network = Network::Mainnet) as fn(&mut Statement),
        |statement| statement.security_domain_id = [7; 32],
        |statement| statement.custody_epoch += 1,
        |statement| statement.slot = 0,
        |statement| statement.slot = 5,
        |statement| statement.share_commitment = [1; 32],
    ] {
        let mut request = fix.request();
        alter(&mut request.statement);
        request.approvals = fix.approve(&request.statement, [1, 3]);
        assert!(fix.relay.rewrap(request).is_none());
    }
    let mut request = fix.request();
    request.envelope = envelope(&rsa(), &fix.share);
    assert!(fix.relay.rewrap(request).is_none());
    let mut request = fix.request();
    request.envelope = envelope(&fix.relay.recipient, &[0x66; 41]);
    assert!(fix.relay.rewrap(request).is_none());
}
