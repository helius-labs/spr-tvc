//! Native Nitro startup. The parent forwards KMS ciphertext over vsock.

use std::{
    future::{pending, Future},
    io,
    num::NonZeroU64,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
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
use openssl::{
    pkey::{PKey, Private},
    rand::rand_bytes,
    rsa::Rsa,
};
use serde::Serialize;
use spr_nitro_nsm::now_ms as nsm_now_ms;
use spr_tvc_protocol::{
    digest::sha256,
    encoding::{decimal_u64, hex, jcs_serialize, parse_strict_json},
    types::{Network, ServiceInfo},
};
use tokio::{
    sync::{oneshot, OwnedSemaphorePermit, Semaphore},
    time::Instant,
};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};
use tower_http::cors::{Any, CorsLayer};
use zeroize::Zeroizing;

use crate::{
    custody::{CustodianPackage, Custody, Recipients, SHARE_COUNT, THRESHOLD},
    custody_relay::{RecoveryProof, Relay, RelayAuthorities, Request as RelayRequest},
    keys::NoteSeed,
    kms_recipient::{open_share, MAX_CMS_BYTES},
    native_crypto::NativePair,
    nitro_http,
    release::NETWORK,
    service::{dispatch_with_crypto, read_operation_body},
    wire::KeyPair,
    Release, Service,
};

const SHARE_FRAME_HEADER: usize = 3;
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(120);
const RELAY_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_SERVING_REQUESTS: usize = 32;
const MAX_ATTESTATION_REQUESTS: usize = 2;
const MAX_SERVING_CONNECTIONS: usize = 64;
const MAX_CUSTODY_CONNECTIONS: usize = 4;
const SERVING_DEADLINE: Duration = Duration::from_secs(5);

mod configuration;

pub use configuration::Config;
use configuration::{read_configuration, Deployment};

pub async fn run(config: Config) -> io::Result<()> {
    let configuration = read_configuration(config.configuration)?;
    if config.check_configuration {
        return Ok(());
    }
    let domain = configuration.security_domain_id;
    let release_id = configuration.release_id;
    match configuration.deployment {
        Deployment::Serve { custody } => {
            let (note_seed, slots) = provision(domain, custody.clone()).await?;
            serve(domain, release_id, custody, note_seed, slots).await
        }
        Deployment::Relay {
            custody_epoch,
            approval_keys,
        } => run_relay(domain, custody_epoch, approval_keys).await,
        Deployment::Initialize {
            recipient_public_keys,
        } => {
            let mut seed = Zeroizing::new([0; 32]);
            rand_bytes(seed.as_mut()).map_err(io::Error::other)?;
            publish_custody(domain, release_id, recipient_public_keys, 1, NoteSeed(seed)).await
        }
        Deployment::Rotate {
            previous,
            recipient_public_keys,
        } => {
            let epoch = previous.epoch + 1;
            let (note_seed, _) = provision(domain, previous).await?;
            publish_custody(domain, release_id, recipient_public_keys, epoch, note_seed).await
        }
    }
}

async fn serve(
    domain: [u8; 32],
    release_id: String,
    custody: Custody,
    note_seed: NoteSeed,
    slots: [u8; THRESHOLD],
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
        now_ms: nsm_now_ms,
    });
    let booted_at_ms = nsm_now_ms().ok_or_else(|| io::Error::other("read Nitro bootstrap time"))?;
    nitro_http::serve(
        ParentListener::bind(44030)?,
        serving_router(
            service,
            BootstrapEvidence {
                slots,
                booted_at_ms,
            },
            Arc::new(OperationTraffic::new()),
        ),
        MAX_SERVING_CONNECTIONS,
        pending(),
    )
    .await;
    Ok(())
}

#[derive(Clone, Copy)]
struct BootstrapEvidence {
    slots: [u8; THRESHOLD],
    booted_at_ms: u64,
}

struct OperationTraffic {
    requests: Semaphore,
    worker: Arc<Semaphore>,
}

impl OperationTraffic {
    fn new() -> Self {
        Self {
            requests: Semaphore::new(MAX_SERVING_REQUESTS),
            worker: Arc::new(Semaphore::new(1)),
        }
    }
}

fn serving_router(
    service: Arc<Service>,
    bootstrap: BootstrapEvidence,
    operations: Arc<OperationTraffic>,
) -> Router {
    let attestation = Router::new()
        .route("/v1/nitro/attestation", post(client_attestation))
        .layer(DefaultBodyLimit::max(32))
        .layer(Extension(bootstrap))
        .layer(Extension(Arc::new(Semaphore::new(1))))
        .layer(middleware::from_fn_with_state(
            Arc::new(Semaphore::new(MAX_ATTESTATION_REQUESTS)),
            limit_serving_request,
        ));
    Router::new()
        .fallback(serve_request)
        .layer(Extension(operations))
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

async fn serve_request(
    State(service): State<Arc<Service>>,
    Extension(operations): Extension<Arc<OperationTraffic>>,
    request: Request,
) -> Response {
    dispatch_with_crypto(service, request, |operation, service, body| async move {
        within_request_budget(&operations.requests, async {
            let body = match read_operation_body(&service, body).await {
                Ok(body) => body,
                Err(error) => return error.into_response(),
            };
            let Ok(permit) = operations.worker.clone().acquire_owned().await else {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            run_with_permit(permit, move || operation(&service, &body))
                .await
                .unwrap_or_else(IntoResponse::into_response)
        })
        .await
    })
    .await
}

async fn limit_serving_request(
    State(capacity): State<Arc<Semaphore>>,
    request: Request,
    next: Next,
) -> Response {
    within_request_budget(&capacity, next.run(request)).await
}

async fn within_request_budget(
    capacity: &Semaphore,
    work: impl Future<Output = Response>,
) -> Response {
    let Ok(_permit) = capacity.try_acquire() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    tokio::select! {
        biased;
        _ = tokio::time::sleep(SERVING_DEADLINE) => StatusCode::REQUEST_TIMEOUT.into_response(),
        response = work => response,
    }
}

type RestoredSeed = (NoteSeed, [u8; THRESHOLD]);

struct Recipient {
    private: PKey<Private>,
    sender: oneshot::Sender<RestoredSeed>,
}

struct Bootstrap {
    recipient: Mutex<Option<Recipient>>,
    domain: [u8; 32],
    custody: Custody,
    deadline: Instant,
}

impl Bootstrap {
    fn pending(&self) -> Result<MutexGuard<'_, Option<Recipient>>, StatusCode> {
        let pending = self
            .recipient
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if Instant::now() >= self.deadline {
            return Err(StatusCode::GONE);
        }
        Ok(pending)
    }

    fn private_key(&self) -> Result<PKey<Private>, StatusCode> {
        self.pending()?
            .as_ref()
            .map(|recipient| recipient.private.clone())
            .ok_or(StatusCode::GONE)
    }

    fn complete(&self, restored: RestoredSeed) -> Result<[u8; THRESHOLD], StatusCode> {
        let slots = restored.1;
        let recipient = self.pending()?.take().ok_or(StatusCode::GONE)?;
        recipient
            .sender
            .send(restored)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        Ok(slots)
    }
}

async fn provision(domain: [u8; 32], custody: Custody) -> io::Result<RestoredSeed> {
    let (sender, seed) = oneshot::channel();
    let private =
        PKey::from_rsa(Rsa::generate(2048).map_err(io::Error::other)?).map_err(io::Error::other)?;
    let deadline = Instant::now() + BOOTSTRAP_TIMEOUT;
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
            deadline,
        }));
    let listener = ParentListener::bind(44031)?;
    let (shutdown, shutdown_signal) = oneshot::channel::<()>();
    let server = nitro_http::serve(listener, app, MAX_CUSTODY_CONNECTIONS, async {
        let _ = shutdown_signal.await;
    });
    tokio::pin!(server);
    let seed = tokio::select! {
        biased;
        seed = seed => seed.map_err(io::Error::other)?,
        () = &mut server => {
            return Err(io::Error::other("seed listener stopped"));
        }
        _ = tokio::time::sleep_until(deadline) => {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "seed provisioning timed out"));
        }
    };
    let _ = shutdown.send(());
    server.await;
    Ok(seed)
}

async fn run_relay(
    domain: [u8; 32],
    epoch: NonZeroU64,
    authorities: RelayAuthorities,
) -> io::Result<()> {
    let recipient =
        PKey::from_rsa(Rsa::generate(2048).map_err(io::Error::other)?).map_err(io::Error::other)?;
    let relay = Arc::new(Relay::new(recipient, NETWORK, domain, epoch, authorities)?);
    let deadline = Instant::now() + RELAY_TIMEOUT;
    let app = Router::new()
        .route("/recipient", post(relay_recipient))
        .route("/rewrap", post(relay_rewrap))
        .route("/prove", post(relay_prove))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(Extension(deadline))
        .layer(Extension(Arc::new(Semaphore::new(1))))
        .with_state(relay);
    nitro_http::serve(
        ParentListener::bind(44031)?,
        app,
        MAX_CUSTODY_CONNECTIONS,
        tokio::time::sleep_until(deadline),
    )
    .await;
    Ok(())
}

async fn relay_recipient(
    State(relay): State<Arc<Relay>>,
    Extension(worker): Extension<Arc<Semaphore>>,
    Extension(deadline): Extension<Instant>,
    nonce: Bytes,
) -> Reply<Vec<u8>> {
    if nonce.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    with_worker_before(worker, deadline, move || {
        let public = relay
            .public_key()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let binding = sha256(b"SPR/native-nitro/relay-recipient/v1");
        attest(Some(&public), Some(&binding), Some(&nonce))
    })
    .await
}

async fn relay_rewrap(
    State(relay): State<Arc<Relay>>,
    Extension(worker): Extension<Arc<Semaphore>>,
    Extension(deadline): Extension<Instant>,
    body: Bytes,
) -> Reply<Vec<u8>> {
    let json = std::str::from_utf8(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let request: RelayRequest = parse_strict_json(json).map_err(|_| StatusCode::BAD_REQUEST)?;
    with_worker_before(worker, deadline, move || {
        let ciphertext = relay
            .rewrap(request, nsm_now_ms)
            .ok_or(StatusCode::BAD_REQUEST)?;
        Ok(([(CONTENT_TYPE, "application/octet-stream")], ciphertext))
    })
    .await
}

async fn relay_prove(
    State(relay): State<Arc<Relay>>,
    Extension(worker): Extension<Arc<Semaphore>>,
    Extension(deadline): Extension<Instant>,
    body: Bytes,
) -> Reply<Vec<u8>> {
    let json = std::str::from_utf8(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let request: RecoveryProof = parse_strict_json(json).map_err(|_| StatusCode::BAD_REQUEST)?;
    with_worker_before(worker, deadline, move || {
        let binding = relay.prove(&request).ok_or(StatusCode::BAD_REQUEST)?;
        attest(None, Some(&binding), Some(&request.nonce))
    })
    .await
}

async fn kms_attestation(
    State(state): State<Arc<Bootstrap>>,
    Extension(worker): Extension<Arc<Semaphore>>,
) -> Reply<Vec<u8>> {
    with_worker_before(worker, state.deadline, move || {
        let public = state
            .private_key()?
            .public_key_to_der()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        attest(Some(&public), None, None)
    })
    .await
}

async fn accept_shares(
    State(state): State<Arc<Bootstrap>>,
    Extension(worker): Extension<Arc<Semaphore>>,
    body: Bytes,
) -> Reply<Vec<u8>> {
    let verify = state.clone();
    let restored = with_worker(worker, move || {
        let private = verify.private_key()?;
        open_shares(&private, &body, &verify.domain, &verify.custody).ok_or(StatusCode::BAD_REQUEST)
    })
    .await?;
    let slots = state.complete(restored)?;
    Ok(([(CONTENT_TYPE, "application/octet-stream")], slots.to_vec()))
}

fn open_shares(
    private: &PKey<Private>,
    mut frame: &[u8],
    domain: &[u8; 32],
    custody: &Custody,
) -> Option<RestoredSeed> {
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
        if let Some(share) = open_share(private, envelope) {
            shares.push((slot, share));
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
    network: Network,
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
    with_worker(worker, move || {
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ServingBoot<'a> {
    info: &'a ServiceInfo,
    bootstrap_slots: [u8; THRESHOLD],
    #[serde(with = "decimal_u64")]
    booted_at_ms: u64,
}

async fn client_attestation(
    State(service): State<Arc<Service>>,
    Extension(bootstrap): Extension<BootstrapEvidence>,
    Extension(worker): Extension<Arc<Semaphore>>,
    nonce: Bytes,
) -> Reply<String> {
    if nonce.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let discovery = jcs_serialize(&ServingBoot {
        info: &service.info,
        bootstrap_slots: bootstrap.slots,
        booted_at_ms: bootstrap.booted_at_ms,
    })
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let public = service.ephemeral.public_bytes();
    with_worker(worker, move || {
        attested_json(
            "SPR/native-nitro/discovery/v1",
            "boot",
            &discovery,
            Some(public),
            nonce,
        )
    })
    .await
}

async fn with_worker_before<T: Send + 'static>(
    worker: Arc<Semaphore>,
    deadline: Instant,
    work: impl FnOnce() -> Result<T, StatusCode> + Send + 'static,
) -> Result<T, StatusCode> {
    let reply = with_worker(worker, move || {
        if Instant::now() >= deadline {
            return Err(StatusCode::GONE);
        }
        work()
    })
    .await;
    if Instant::now() >= deadline {
        return Err(StatusCode::GONE);
    }
    reply
}

async fn with_worker<T: Send + 'static>(
    worker: Arc<Semaphore>,
    work: impl FnOnce() -> Result<T, StatusCode> + Send + 'static,
) -> Result<T, StatusCode> {
    let permit = worker
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    run_with_permit(permit, work).await?
}

async fn run_with_permit<T: Send + 'static>(
    permit: OwnedSemaphorePermit,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, StatusCode> {
    tokio::task::spawn_blocking(move || {
        // Keep the slot until the worker exits, even if its caller disconnects.
        let _permit = permit;
        work()
    })
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
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
    let (_, evidence) = attest(public.as_deref(), Some(&binding), Some(&nonce))?;
    let evidence = spr_tvc_protocol::encoding::encode_lower_hex(&evidence);
    Ok((
        [(CONTENT_TYPE, "application/json")],
        format!(r#"{{"evidence":"{evidence}","{field}":{value}}}"#),
    ))
}

fn attest(public: Option<&[u8]>, user_data: Option<&[u8]>, nonce: Option<&[u8]>) -> Reply<Vec<u8>> {
    let document = spr_nitro_nsm::attest(public, user_data, nonce)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(([(CONTENT_TYPE, "application/cbor")], document))
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
pub(crate) mod tests;

#[cfg(test)]
#[path = "../tests/unit/nitro_traffic.rs"]
mod traffic_tests;
