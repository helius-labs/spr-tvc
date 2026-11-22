use openssl::{
    encrypt::Decrypter,
    hash::MessageDigest,
    rsa::{Padding, Rsa},
};
use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

use crate::kms_recipient::tests::envelope;

use super::*;

const DOMAIN: [u8; 32] = [0xbb; 32];
const EPOCH: u64 = 7;
const EXPIRES: u64 = 1_795_290_720;
const BEFORE_EXPIRY_MS: u64 = EXPIRES * 1_000 - 1;

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
        assert!(RelayAuthorities::parse([pins[0]; 3]).is_err());
        let authorities = RelayAuthorities::parse(pins).unwrap();
        let relay = Relay::new(
            rsa(),
            Network::Devnet,
            DOMAIN,
            NonZeroU64::new(EPOCH).unwrap(),
            authorities,
        )
        .unwrap();
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
            expires_at: EXPIRES,
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
                signature: signature.to_der().as_bytes().to_vec(),
            }
        })
    }

    fn rewrap(&self, request: Request) -> Option<Vec<u8>> {
        self.relay.rewrap(request, || Some(BEFORE_EXPIRY_MS))
    }
}

#[test]
fn rewraps_a_committed_share_for_the_two_signers_exact_destination() {
    let fix = Fixture::new();
    let ciphertext = fix.rewrap(fix.request()).unwrap();
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
    assert!(fix.rewrap(request).is_none());
    let mut request = fix.request();
    request.approvals = fix.approve(&request.statement, [1, 1]);
    assert!(fix.rewrap(request).is_none());
    let mut request = fix.request();
    request.approvals[0].authority = 2;
    assert!(fix.rewrap(request).is_none());
    let mut request = fix.request();
    request.statement.relay_key_id = [9; 32];
    request.approvals = fix.approve(&request.statement, [1, 3]);
    assert!(fix.rewrap(request).is_none());
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
        assert!(fix.rewrap(request).is_none());
    }
    let mut request = fix.request();
    request.envelope = envelope(&rsa(), &fix.share);
    assert!(fix.rewrap(request).is_none());
    let mut request = fix.request();
    request.envelope = envelope(&fix.relay.recipient, &[0x66; 41]);
    assert!(fix.rewrap(request).is_none());
}

#[test]
fn refuses_to_release_after_the_signed_deadline_or_without_nitro_time() {
    let fix = Fixture::new();
    let mut changed = fix.request();
    changed.statement.expires_at += 1;
    assert!(fix.rewrap(changed).is_none());
    for expires in [0, 1 << 53] {
        let mut invalid = fix.request();
        invalid.statement.expires_at = expires;
        invalid.approvals = fix.approve(&invalid.statement, [1, 3]);
        assert!(fix.rewrap(invalid).is_none());
    }

    for mut ticks in [
        [Some(EXPIRES * 1_000), Some(BEFORE_EXPIRY_MS)].into_iter(),
        [Some(BEFORE_EXPIRY_MS), Some(EXPIRES * 1_000)].into_iter(),
        [None, Some(BEFORE_EXPIRY_MS)].into_iter(),
        [Some(BEFORE_EXPIRY_MS), None].into_iter(),
    ] {
        assert!(fix
            .relay
            .rewrap(fix.request(), || ticks.next().unwrap())
            .is_none());
    }
}

#[test]
fn proves_a_recovered_share_without_returning_it() {
    let fix = Fixture::new();
    let request = fix.request();
    let mut proof = RecoveryProof {
        slot: request.statement.slot,
        share_commitment: request.statement.share_commitment,
        envelope: request.envelope,
        nonce: [0x88; 32],
    };
    let expected = sha256(
        &[
            b"SPR/native-nitro/relay-share-proof/v1devnet".as_slice(),
            &DOMAIN,
            &EPOCH.to_be_bytes(),
            &[4],
            &proof.share_commitment,
            &fix.relay.relay_key_id,
            &sha256(&proof.envelope),
        ]
        .concat(),
    );
    assert_eq!(fix.relay.prove(&proof), Some(expected));
    assert_eq!(Fixture::new().relay.prove(&proof), None);
    proof.envelope = envelope(&fix.relay.recipient, &fix.share);
    let another_envelope = fix.relay.prove(&proof).unwrap();
    assert_ne!(another_envelope, expected);
    proof.slot = 3;
    assert_eq!(fix.relay.prove(&proof), None);
    proof.slot = 4;
    proof.share_commitment[4] ^= 1;
    assert_eq!(fix.relay.prove(&proof), None);
}
