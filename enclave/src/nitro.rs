//! Native Nitro startup. The parent forwards KMS ciphertext over vsock.

use std::{
    fs::File,
    future::pending,
    io::{self, Read},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use aws_nitro_enclaves_nsm_api::{
    api::{Request as NsmRequest, Response as NsmResponse},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{header, header::CONTENT_TYPE, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Router,
};
use clap::Parser;
use openssl::{
    cms::CmsContentInfo,
    pkey::{PKey, Private},
    rand::rand_bytes,
    rsa::Rsa,
};
use serde::{Deserialize, Serialize};
use spr_tvc_protocol::{
    digest::sha256,
    encoding::{hex, jcs_serialize, parse_strict_json},
};
use tokio::sync::{oneshot, Semaphore};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};
use tower_http::cors::{Any, CorsLayer};
use zeroize::Zeroizing;

use crate::{
    custody::{CustodianPackage, Custody, Recipients, SHARE_COUNT, THRESHOLD},
    keys::NoteSeed,
    native_crypto::NativePair,
    nitro_http,
    release::NETWORK,
    service::dispatch,
    wire::KeyPair,
    Release, Service,
};

const MAX_CMS_BYTES: usize = 6144;
const SHARE_FRAME_HEADER: usize = 3;
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_SERVING_REQUESTS: usize = 32;
const MAX_ATTESTATION_REQUESTS: usize = 2;
const MAX_SERVING_CONNECTIONS: usize = 64;
const MAX_CUSTODY_CONNECTIONS: usize = 4;
const SERVING_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Parser)]
pub struct Config {
    #[arg(default_value = "/configuration.json")]
    configuration: PathBuf,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Configuration {
    #[serde(with = "hex")]
    security_domain_id: [u8; 32],
    release_id: String,
    deployment: Deployment,
}

#[derive(Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "lowercase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum Deployment {
    Serve {
        custody: Custody,
    },
    Initialize {
        #[serde(with = "hex")]
        recipient_public_keys: Vec<Vec<u8>>,
    },
    Rotate {
        previous: Custody,
        #[serde(with = "hex")]
        recipient_public_keys: Vec<Vec<u8>>,
    },
}

pub async fn run(config: Config) -> io::Result<()> {
    const MAX_CONFIG: u64 = 24 * 1024;
    let mut json = String::new();
    File::open(config.configuration)?
        .take(MAX_CONFIG + 1)
        .read_to_string(&mut json)?;
    if json.len() as u64 > MAX_CONFIG {
        return Err(io::Error::other("configuration exceeds size limit"));
    }
    let config: Configuration = parse_strict_json(&json).map_err(io::Error::other)?;
    let domain = config.security_domain_id;
    let release_id = config.release_id;
    if domain == [0; 32]
        || release_id.is_empty()
        || release_id.len() > 64
        || !release_id.as_bytes()[0].is_ascii_alphanumeric()
        || !release_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(io::Error::other("invalid security domain or release ID"));
    }
    match config.deployment {
        Deployment::Serve { custody } => {
            custody.validate()?;
            let note_seed = provision(domain, custody.clone()).await?;
            serve(domain, release_id, custody, note_seed).await
        }
        Deployment::Initialize {
            recipient_public_keys,
        } => {
            let recipients = Recipients::parse(&recipient_public_keys)?;
            let mut seed = Zeroizing::new([0; 32]);
            rand_bytes(seed.as_mut()).map_err(io::Error::other)?;
            publish_custody(domain, release_id, recipients, 1, NoteSeed(seed)).await
        }
        Deployment::Rotate {
            previous,
            recipient_public_keys,
        } => {
            previous.validate()?;
            let recipients = Recipients::parse(&recipient_public_keys)?;
            let epoch = previous
                .epoch
                .checked_add(1)
                .ok_or_else(|| io::Error::other("custody epoch exhausted"))?;
            let note_seed = provision(domain, previous).await?;
            publish_custody(domain, release_id, recipients, epoch, note_seed).await
        }
    }
}

async fn serve(
    domain: [u8; 32],
    release_id: String,
    custody: Custody,
    note_seed: NoteSeed,
) -> io::Result<()> {
    let executable = sha256(&std::fs::read(std::env::current_exe()?)?);
    let release_identity = sha256(
        &[
            b"SPR/native-nitro/release/v1".as_slice(),
            &executable,
            &custody.note_seed_commitment,
            &custody.digest()?,
        ]
        .concat(),
    );
    let transport =
        NativePair::generate().map_err(|_| io::Error::other("generate transport key"))?;
    let ephemeral = NativePair::generate().map_err(|_| io::Error::other("generate proof key"))?;
    let info = Release {
        security_domain_id: domain,
        release_id,
        quorum_key_id: spr_tvc_protocol::encoding::encode_lower_hex(&sha256(&transport.public)),
        quorum_key_epoch: custody.epoch,
    }
    .service_info(release_identity, executable, transport.public.clone());
    let service = Arc::new(Service {
        info,
        ephemeral: KeyPair::Native(ephemeral),
        quorum: KeyPair::Native(transport),
        note_seed,
    });
    nitro_http::serve(
        ParentListener::bind(44030)?,
        serving_router(service),
        MAX_SERVING_CONNECTIONS,
        pending(),
    )
    .await;
    Ok(())
}

fn serving_router(service: Arc<Service>) -> Router {
    let attestation = Router::new()
        .route("/v1/nitro/attestation", post(client_attestation))
        .layer(DefaultBodyLimit::max(32))
        .layer(Extension(Arc::new(Semaphore::new(1))))
        .layer(middleware::from_fn_with_state(
            Arc::new(Semaphore::new(MAX_ATTESTATION_REQUESTS)),
            limit_serving_request,
        ));
    Router::new()
        .fallback(dispatch)
        .layer(middleware::from_fn_with_state(
            Arc::new(Semaphore::new(MAX_SERVING_REQUESTS)),
            limit_serving_request,
        ))
        .merge(attestation)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::POST])
                .allow_headers([CONTENT_TYPE])
                .expose_headers([header::RETRY_AFTER]),
        )
        .with_state(service)
}

async fn limit_serving_request(
    State(capacity): State<Arc<Semaphore>>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(_permit) = capacity.try_acquire() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    match tokio::time::timeout(SERVING_DEADLINE, next.run(request)).await {
        Ok(response) => response,
        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
    }
}

struct Recipient {
    private: PKey<Private>,
    sender: oneshot::Sender<NoteSeed>,
}

struct Bootstrap {
    recipient: Mutex<Option<Recipient>>,
    domain: [u8; 32],
    custody: Custody,
}

async fn provision(domain: [u8; 32], custody: Custody) -> io::Result<NoteSeed> {
    let (sender, seed) = oneshot::channel();
    let private =
        PKey::from_rsa(Rsa::generate(2048).map_err(io::Error::other)?).map_err(io::Error::other)?;
    let app = Router::new()
        .route("/recipient", get(kms_attestation))
        .route("/shares", post(accept_shares))
        .layer(DefaultBodyLimit::max(
            SHARE_COUNT * (MAX_CMS_BYTES + SHARE_FRAME_HEADER),
        ))
        .layer(Extension(Arc::new(Semaphore::new(1))))
        .with_state(Arc::new(Bootstrap {
            recipient: Mutex::new(Some(Recipient { private, sender })),
            domain,
            custody,
        }));
    let listener = ParentListener::bind(44031)?;
    let (shutdown, shutdown_signal) = oneshot::channel::<()>();
    let server = nitro_http::serve(listener, app, MAX_CUSTODY_CONNECTIONS, async {
        let _ = shutdown_signal.await;
    });
    tokio::pin!(server);
    let seed = tokio::select! {
        seed = seed => seed.map_err(io::Error::other)?,
        () = &mut server => {
            return Err(io::Error::other("seed listener stopped"));
        }
        _ = tokio::time::sleep(BOOTSTRAP_TIMEOUT) => {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "seed provisioning timed out"));
        }
    };
    let _ = shutdown.send(());
    server.await;
    Ok(seed)
}

async fn kms_attestation(
    State(state): State<Arc<Bootstrap>>,
    Extension(worker): Extension<Arc<Semaphore>>,
) -> Reply<Vec<u8>> {
    let public = state
        .recipient
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .as_ref()
        .ok_or(StatusCode::GONE)?
        .private
        .public_key_to_der()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    issue_attestation(worker, move || attest(Some(public), None, None)).await
}

async fn accept_shares(State(state): State<Arc<Bootstrap>>, body: Bytes) -> Reply<Vec<u8>> {
    let mut pending = state
        .recipient
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let recipient = pending.as_ref().ok_or(StatusCode::GONE)?;
    let (seed, slots) = open_shares(&recipient.private, &body, &state.domain, &state.custody)
        .ok_or(StatusCode::BAD_REQUEST)?;
    let recipient = pending.take().ok_or(StatusCode::GONE)?;
    recipient
        .sender
        .send(seed)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(([(CONTENT_TYPE, "application/octet-stream")], slots.to_vec()))
}

fn open_shares(
    private: &PKey<Private>,
    mut frame: &[u8],
    domain: &[u8; 32],
    custody: &Custody,
) -> Option<(NoteSeed, [u8; THRESHOLD])> {
    let mut shares = Vec::with_capacity(SHARE_COUNT);
    let mut count = 0;
    while !frame.is_empty() {
        count += 1;
        let (&[slot, high, low], rest) = frame.split_first_chunk::<SHARE_FRAME_HEADER>()?;
        let length = usize::from(u16::from_be_bytes([high, low]));
        if count > SHARE_COUNT || !(1..=MAX_CMS_BYTES).contains(&length) {
            return None;
        }
        let (envelope, rest) = rest.split_at_checked(length)?;
        if let Ok(share) = CmsContentInfo::from_der(envelope)
            .and_then(|cms| cms.decrypt_without_cert_check(private))
        {
            shares.push((slot, Zeroizing::new(share)));
        }
        frame = rest;
    }
    if count < THRESHOLD {
        return None;
    }
    custody.restore(
        domain,
        shares.iter().map(|(slot, share)| (*slot, share.as_slice())),
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CustodyResult {
    network: spr_tvc_protocol::types::Network,
    #[serde(with = "hex")]
    security_domain_id: [u8; 32],
    release_id: String,
    custody: Custody,
    packages: Vec<CustodianPackage>,
}

async fn publish_custody(
    domain: [u8; 32],
    release_id: String,
    recipients: Recipients,
    epoch: u64,
    seed: NoteSeed,
) -> io::Result<()> {
    let (custody, packages) = recipients.issue(&domain, epoch, &seed)?;
    drop(seed);
    let result = Arc::new(
        jcs_serialize(&CustodyResult {
            network: NETWORK,
            security_domain_id: domain,
            release_id,
            custody,
            packages,
        })
        .map_err(io::Error::other)?,
    );
    let app = Router::new()
        .route("/custody", post(custody_attestation))
        .layer(DefaultBodyLimit::max(32))
        .layer(Extension(Arc::new(Semaphore::new(1))))
        .with_state(result);
    let _ = tokio::time::timeout(
        Duration::from_secs(300),
        nitro_http::serve(
            ParentListener::bind(44031)?,
            app,
            MAX_CUSTODY_CONNECTIONS,
            pending(),
        ),
    )
    .await;
    Ok(())
}

async fn custody_attestation(
    State(result): State<Arc<String>>,
    Extension(worker): Extension<Arc<Semaphore>>,
    nonce: Bytes,
) -> Reply<String> {
    issue_attestation(worker, move || {
        attested_json(
            "SPR/native-nitro/custody/v1",
            "result",
            &result,
            None,
            nonce,
        )
    })
    .await
}

type Reply<T> = Result<([(axum::http::HeaderName, &'static str); 1], T), StatusCode>;

async fn client_attestation(
    State(service): State<Arc<Service>>,
    Extension(worker): Extension<Arc<Semaphore>>,
    nonce: Bytes,
) -> Reply<String> {
    if nonce.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let discovery = jcs_serialize(&service.info).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let public = service.ephemeral.public_bytes();
    issue_attestation(worker, move || {
        attested_json(
            "SPR/native-nitro/discovery/v1",
            "info",
            &discovery,
            Some(public),
            nonce,
        )
    })
    .await
}

async fn issue_attestation<T: Send + 'static>(
    worker: Arc<Semaphore>,
    generate: impl FnOnce() -> Reply<T> + Send + 'static,
) -> Reply<T> {
    let permit = worker
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    tokio::task::spawn_blocking(move || {
        // Cancellation of the HTTP request must not admit another NSM call.
        let _permit = permit;
        generate()
    })
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
}

fn attested_json(
    domain: &str,
    field: &str,
    value: &str,
    public: Option<Vec<u8>>,
    nonce: Bytes,
) -> Reply<String> {
    if nonce.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let binding = sha256(&[domain.as_bytes(), value.as_bytes()].concat());
    let (_, evidence) = attest(public, Some(binding), Some(nonce.to_vec()))?;
    let evidence = spr_tvc_protocol::encoding::encode_lower_hex(&evidence);
    Ok((
        [(CONTENT_TYPE, "application/json")],
        format!(r#"{{"evidence":"{evidence}","{field}":{value}}}"#),
    ))
}

fn attest(
    public: Option<Vec<u8>>,
    user_data: Option<[u8; 32]>,
    nonce: Option<Vec<u8>>,
) -> Reply<Vec<u8>> {
    let fd = nsm_init();
    if fd < 0 {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let response = nsm_process_request(
        fd,
        NsmRequest::Attestation {
            public_key: public.map(Into::into),
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

#[cfg(test)]
#[path = "../tests/unit/nitro_traffic.rs"]
mod traffic_tests;
