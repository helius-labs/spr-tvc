//! Release a recovered share only to an independently approved public key.

use std::io;

use openssl::{
    cms::CmsContentInfo,
    pkey::{PKey, Private},
};
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use spr_tvc_protocol::{
    digest::sha256,
    encoding::{decimal_u64, hex, jcs_serialize},
    types::Network,
};
use zeroize::Zeroizing;

use crate::custody::{encrypt_share, parse_recipient, valid_share, SHARE_COUNT};

pub(crate) const MAX_CMS_BYTES: usize = 6_144;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Statement {
    network: Network,
    #[serde(with = "hex")]
    security_domain_id: [u8; 32],
    #[serde(with = "decimal_u64")]
    custody_epoch: u64,
    slot: u8,
    #[serde(with = "hex")]
    share_commitment: [u8; 32],
    #[serde(with = "hex")]
    relay_key_id: [u8; 32],
    #[serde(with = "hex")]
    target_digest: [u8; 32],
    #[serde(with = "hex")]
    destination_public_key: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    authority: u8,
    #[serde(with = "hex")]
    signature: [u8; 64],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    statement: Statement,
    approvals: [Approval; 2],
    #[serde(with = "hex")]
    envelope: Vec<u8>,
}

pub(crate) struct Relay {
    recipient: PKey<Private>,
    relay_key_id: [u8; 32],
    domain: [u8; 32],
    epoch: u64,
    network: Network,
    authorities: [VerifyingKey; 3],
}

impl Relay {
    pub(crate) fn new(
        recipient: PKey<Private>,
        network: Network,
        domain: [u8; 32],
        epoch: u64,
        pins: [[u8; 65]; 3],
    ) -> io::Result<Self> {
        if epoch == 0
            || domain == [0; 32]
            || pins.iter().any(|key| key[0] != 4)
            || pins[0] == pins[1]
            || pins[1] == pins[2]
            || pins[0] == pins[2]
        {
            return Err(io::Error::other(
                "invalid relay scope or duplicate authority",
            ));
        }
        let [a, b, c] = pins.map(|key| {
            VerifyingKey::from_sec1_bytes(&key)
                .map_err(|_| io::Error::other("invalid relay authority"))
        });
        let relay_key_id = sha256(&recipient.public_key_to_der().map_err(io::Error::other)?);
        Ok(Self {
            recipient,
            relay_key_id,
            domain,
            epoch,
            network,
            authorities: [a?, b?, c?],
        })
    }

    pub(crate) fn public_key(&self) -> Result<Vec<u8>, openssl::error::ErrorStack> {
        self.recipient.public_key_to_der()
    }

    pub(crate) fn rewrap(&self, request: Request) -> Option<Vec<u8>> {
        let Request {
            statement,
            approvals,
            envelope,
        } = request;
        if statement.network != self.network
            || statement.security_domain_id != self.domain
            || statement.custody_epoch != self.epoch
            || statement.relay_key_id != self.relay_key_id
            || !(1..=SHARE_COUNT).contains(&usize::from(statement.slot))
            || statement.target_digest == [0; 32]
            || approvals[0].authority == approvals[1].authority
            || !(1..=MAX_CMS_BYTES).contains(&envelope.len())
        {
            return None;
        }
        let digest = signing_digest(&statement)?;
        for Approval {
            authority,
            signature,
        } in approvals
        {
            let key = self
                .authorities
                .get(usize::from(authority).checked_sub(1)?)?;
            let sig = Signature::from_slice(&signature).ok()?;
            if sig.normalize_s() != sig || key.verify_prehash(&digest, &sig).is_err() {
                return None;
            }
        }
        let destination = parse_recipient(&statement.destination_public_key).ok()?;
        let cms = CmsContentInfo::from_der(&envelope).ok()?;
        let share = Zeroizing::new(cms.decrypt_without_cert_check(&self.recipient).ok()?);
        if !valid_share(
            &self.domain,
            self.epoch,
            statement.slot,
            &share,
            &statement.share_commitment,
        ) {
            return None;
        }
        encrypt_share(&destination, &share).ok()
    }
}

fn signing_digest(statement: &Statement) -> Option<[u8; 32]> {
    let canonical = jcs_serialize(statement).ok()?;
    Some(sha256(
        &[
            b"SPR/native-nitro/relay-release/v1".as_slice(),
            canonical.as_bytes(),
        ]
        .concat(),
    ))
}

#[cfg(test)]
#[path = "../tests/unit/nitro_custody_relay.rs"]
mod tests;
