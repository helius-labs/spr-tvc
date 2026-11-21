//! Native Nitro startup. The parent forwards KMS ciphertext over vsock.

use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

use aws_nitro_enclaves_nsm_api::{
    api::{Request as NsmRequest, Response as NsmResponse},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{header::CONTENT_TYPE, StatusCode},
    routing::{get, post},
    Router,
};
use clap::Parser;
use openssl::{
    cms::CmsContentInfo,
    pkey::{PKey, Private},
    rsa::Rsa,
};
use serde::Serialize;
use spr_tvc_protocol::{digest::sha256, encoding::jcs_serialize, types::ServiceInfo};
use tokio::sync::oneshot;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};
use zeroize::Zeroizing;

use crate::{
    keys::NoteSeed, native_crypto::NativePair, service::dispatch, wire::KeyPair, Release, Service,
};

const MAX_CMS_BYTES: usize = 6144;
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Parser)]
pub struct Config {
    #[arg(long, value_parser = crate::release::security_domain_id)]
    security_domain_id: [u8; 32],
    #[arg(long, value_parser = crate::release::nonempty)]
    release_id: String,
    #[arg(long, value_parser = crate::release::security_domain_id)]
    share_1_sha256: [u8; 32],
    #[arg(long, value_parser = crate::release::security_domain_id)]
    share_2_sha256: [u8; 32],
}

pub async fn run(config: Config) -> io::Result<()> {
    let executable = sha256(&std::fs::read(std::env::current_exe()?)?);
    let commitments = [config.share_1_sha256, config.share_2_sha256];
    if commitments[0] == commitments[1] || commitments.contains(&[0; 32]) {
        return Err(io::Error::other("invalid share commitments"));
    }
    let seed_commitment = sha256(
        &[
            b"SPR/native-nitro/note-seed/v1".as_slice(),
            &commitments[0],
            &commitments[1],
        ]
        .concat(),
    );
    let release_identity = sha256(
        &[
            b"SPR/native-nitro/release/v1".as_slice(),
            &executable,
            &seed_commitment,
        ]
        .concat(),
    );
    let note_seed = provision(commitments).await?;
    let transport =
        NativePair::generate().map_err(|_| io::Error::other("generate transport key"))?;
    let ephemeral = NativePair::generate().map_err(|_| io::Error::other("generate proof key"))?;
    let info = Release {
        security_domain_id: config.security_domain_id,
        release_id: config.release_id,
        quorum_key_id: spr_tvc_protocol::encoding::encode_lower_hex(&sha256(&transport.public)),
        quorum_key_epoch: 1,
    }
    .service_info(release_identity, executable, transport.public.clone());
    let service = Arc::new(Service {
        info,
        ephemeral: KeyPair::Native(ephemeral),
        quorum: KeyPair::Native(transport),
        note_seed,
    });
    let app = Router::new()
        .route(
            "/v1/nitro/attestation",
            post(client_attestation).layer(DefaultBodyLimit::max(32)),
        )
        .fallback(dispatch)
        .with_state(service);
    axum::serve(ParentListener::bind(44030)?, app).await
}

struct Recipient {
    private: PKey<Private>,
    sender: oneshot::Sender<NoteSeed>,
}

struct Bootstrap {
    recipient: Mutex<Option<Recipient>>,
    commitments: [[u8; 32]; 2],
}

async fn provision(commitments: [[u8; 32]; 2]) -> io::Result<NoteSeed> {
    let (sender, seed) = oneshot::channel();
    let private =
        PKey::from_rsa(Rsa::generate(2048).map_err(io::Error::other)?).map_err(io::Error::other)?;
    let app = Router::new()
        .route("/recipient", get(kms_attestation))
        .route("/shares", post(accept_shares))
        .layer(DefaultBodyLimit::max(2 * MAX_CMS_BYTES + 2))
        .with_state(Arc::new(Bootstrap {
            recipient: Mutex::new(Some(Recipient { private, sender })),
            commitments,
        }));
    let listener = ParentListener::bind(44031)?;
    let (shutdown, shutdown_signal) = oneshot::channel::<()>();
    let mut server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_signal.await;
            })
            .await
    });
    let seed = tokio::select! {
        seed = seed => seed.map_err(io::Error::other)?,
        stopped = &mut server => {
            stopped.map_err(io::Error::other)??;
            return Err(io::Error::other("seed listener stopped"));
        }
        _ = tokio::time::sleep(BOOTSTRAP_TIMEOUT) => {
            server.abort();
            return Err(io::Error::new(io::ErrorKind::TimedOut, "seed provisioning timed out"));
        }
    };
    let _ = shutdown.send(());
    match tokio::time::timeout(Duration::from_secs(5), &mut server).await {
        Ok(result) => result.map_err(io::Error::other)??,
        Err(_) => server.abort(),
    }
    Ok(seed)
}

async fn kms_attestation(State(state): State<Arc<Bootstrap>>) -> Evidence {
    let public = state
        .recipient
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .as_ref()
        .ok_or(StatusCode::GONE)?
        .private
        .public_key_to_der()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    attest(public, None, None)
}

async fn accept_shares(
    State(state): State<Arc<Bootstrap>>,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    let mut pending = state
        .recipient
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let recipient = pending.as_ref().ok_or(StatusCode::GONE)?;
    let seed = open_shares(&recipient.private, &body, &state.commitments)
        .ok_or(StatusCode::BAD_REQUEST)?;
    let recipient = pending.take().ok_or(StatusCode::GONE)?;
    recipient
        .sender
        .send(seed)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(StatusCode::NO_CONTENT)
}

fn open_shares(
    private: &PKey<Private>,
    body: &[u8],
    commitments: &[[u8; 32]; 2],
) -> Option<NoteSeed> {
    let (length, rest) = body.split_first_chunk::<2>()?;
    let (first, second) = rest.split_at_checked(u16::from_be_bytes(*length).into())?;
    let open = |envelope: &[u8]| {
        if !(1..=MAX_CMS_BYTES).contains(&envelope.len()) {
            return None;
        }
        CmsContentInfo::from_der(envelope)
            .and_then(|cms| cms.decrypt_without_cert_check(private))
            .map(Zeroizing::new)
            .ok()
    };
    let first = open(first)?;
    let second = open(second)?;
    if first.len() != 32
        || second.len() != 32
        || openssl::memcmp::eq(&first, &[0u8; 32])
        || openssl::memcmp::eq(&second, &[0u8; 32])
        || !openssl::memcmp::eq(&sha256(&first), &commitments[0])
        || !openssl::memcmp::eq(&sha256(&second), &commitments[1])
    {
        return None;
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    for ((byte, left), right) in seed.iter_mut().zip(first.iter()).zip(second.iter()) {
        *byte = left ^ right;
    }
    Some(NoteSeed(seed))
}

type Evidence = Result<([(axum::http::HeaderName, &'static str); 1], Vec<u8>), StatusCode>;

#[derive(Serialize)]
struct AttestedDiscovery<'a> {
    info: &'a ServiceInfo,
    evidence: String,
}

async fn client_attestation(
    State(service): State<Arc<Service>>,
    nonce: Bytes,
) -> Result<([(axum::http::HeaderName, &'static str); 1], String), StatusCode> {
    if nonce.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let discovery = jcs_serialize(&service.info).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let binding = sha256(
        &[
            b"SPR/native-nitro/discovery/v1".as_slice(),
            discovery.as_bytes(),
        ]
        .concat(),
    );
    let (_, evidence) = attest(
        service.ephemeral.public_bytes(),
        Some(binding),
        Some(nonce.to_vec()),
    )?;
    let body = jcs_serialize(&AttestedDiscovery {
        info: &service.info,
        evidence: spr_tvc_protocol::encoding::encode_lower_hex(&evidence),
    })
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(([(CONTENT_TYPE, "application/json")], body))
}

fn attest(public: Vec<u8>, user_data: Option<[u8; 32]>, nonce: Option<Vec<u8>>) -> Evidence {
    let fd = nsm_init();
    if fd < 0 {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let response = nsm_process_request(
        fd,
        NsmRequest::Attestation {
            public_key: Some(public.into()),
            user_data: user_data.map(|value| value.to_vec().into()),
            nonce: nonce.map(Into::into),
        },
    );
    nsm_exit(fd);
    match response {
        NsmResponse::Attestation { document } => {
            Ok(([(CONTENT_TYPE, "application/cbor")], document))
        }
        _ => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

// AWS assigns CID 3 to the EC2 parent. Linux VMADDR_CID_HOST is CID 2.
const EC2_PARENT_CID: u32 = 3;

struct ParentListener(VsockListener);

impl ParentListener {
    fn bind(port: u32) -> io::Result<Self> {
        VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port)).map(Self)
    }
}

impl axum::serve::Listener for ParentListener {
    type Io = VsockStream;
    type Addr = VsockAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.0.accept().await {
                Ok((stream, address)) if address.cid() == EC2_PARENT_CID => {
                    return (stream, address)
                }
                Ok(_) => (),
                Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.0.local_addr()
    }
}

#[cfg(test)]
#[path = "../tests/unit/nitro_bootstrap.rs"]
mod tests;
