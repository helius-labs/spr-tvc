use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::http::{HeaderValue, StatusCode};
use bytes::Bytes;
use cadence_macros::statsd_count;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spr_tvc_wire::EncryptedRequest;
use spr_tvc_wire::constants::SHA256_LEN;

use crate::error::ApiError;
use crate::project::ProjectId;
use crate::upstream::Forwarded;

const KEY_PREFIX: &str = "tvc-gateway:replay:";
const REDIS_TIMEOUT: Duration = Duration::from_millis(500);
const RUNNING: &str = "running";
/// The largest answer the ledger keeps. A larger one is not kept, and a resend
/// runs again: only `Decrypt`, `Derive`, `TransactionKeys` and `Prove` answer
/// this much, and running them twice gives the same answer or a new sealing
/// of the same proof. A `Bootstrap` answer, which must not run twice, is a few
/// kilobytes.
pub const MAX_KEPT_ANSWER_BYTES: usize = 64 * 1024;

/// What the enclave did with an operation: its answer, or the failure that
/// left it unknown.
pub type Outcome = Result<Forwarded, ApiError>;

/// The digest of an application route, a project, and an encrypted request
/// envelope it claimed. Every variable-length component is length-prefixed so
/// different routes, projects, quorum keys, epochs, versions, or ciphertexts
/// cannot collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key([u8; SHA256_LEN]);

impl Key {
    fn of(application: &str, project: &ProjectId, request: &EncryptedRequest) -> Self {
        let mut digest = Sha256::new();
        let feed = |digest: &mut Sha256, bytes: &[u8]| {
            digest.update((bytes.len() as u64).to_be_bytes());
            digest.update(bytes);
        };
        feed(&mut digest, application.as_bytes());
        feed(&mut digest, project.as_str().as_bytes());
        digest.update([request.version]);
        feed(&mut digest, request.quorum_key_id.as_bytes());
        digest.update(request.quorum_key_epoch.to_be_bytes());
        feed(&mut digest, &request.ciphertext);
        Self(digest.finalize().into())
    }
}

#[derive(Debug)]
pub enum Claim {
    /// The project sent no request with the ciphertext within the window.
    /// This one now holds it, and must record its outcome or release it.
    New(Key),
    /// A request from the project sent it, and this was the outcome.
    Answered(Outcome),
}

/// The first outcome of each project's `/operations` ciphertext within the
/// window, so a resent operation gets that outcome instead of running twice.
/// Applications and projects do not share entries, so none can claim another's
/// ciphertext first.
pub enum ReplayLedger {
    Local(LocalLedger),
    Shared(SharedLedger),
}

impl ReplayLedger {
    pub async fn connect(
        window: Duration,
        max_entries: usize,
        redis_url: Option<&str>,
    ) -> anyhow::Result<Self> {
        let Some(url) = redis_url else {
            return Ok(Self::Local(LocalLedger::new(window, max_entries)));
        };
        let connection = ConnectionManager::new(redis::Client::open(url)?).await?;
        Ok(Self::Shared(SharedLedger {
            connection,
            window_secs: window.as_secs().max(1),
        }))
    }

    /// Refuses a request the project's earlier call on this application
    /// is still running. `application` is the gateway route prefix
    /// (`/v1/private-wallet` or `/v1/decryption`).
    pub async fn claim(
        &self,
        application: &str,
        project: &ProjectId,
        request: &EncryptedRequest,
    ) -> Result<Claim, ApiError> {
        let key = Key::of(application, project, request);
        let claim = match self {
            Self::Local(ledger) => ledger.claim(key, Instant::now()),
            Self::Shared(ledger) => ledger.claim(key).await,
        };
        match &claim {
            Err(ApiError::OperationInProgress) => {
                statsd_count!("operations.in_progress", 1);
            }
            Ok(Claim::Answered(_)) => {
                statsd_count!("operations.replayed", 1);
            }
            _ => {}
        }
        claim
    }

    /// Records the outcome of a claimed ciphertext. If that fails, the claim
    /// stands until the window ends, and a resend gets `OperationInProgress`.
    /// An answer above [`MAX_KEPT_ANSWER_BYTES`] releases the claim instead.
    pub async fn record(&self, key: Key, outcome: &Outcome) {
        if outcome
            .as_ref()
            .is_ok_and(|answer| answer.body.len() > MAX_KEPT_ANSWER_BYTES)
        {
            statsd_count!("operations.answer_not_kept", 1);
            return self.release(key).await;
        }
        match self {
            Self::Local(ledger) => ledger.record(key, outcome),
            Self::Shared(ledger) => ledger.record(key, outcome).await,
        }
    }

    /// Gives up a claim whose request never reached the enclave.
    pub async fn release(&self, key: Key) {
        match self {
            Self::Local(ledger) => ledger.release(key),
            Self::Shared(ledger) => ledger.release(key).await,
        }
    }
}

/// An outcome as the shared ledger stores it.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Record {
    Answered {
        status: u16,
        content_type: String,
        body: String,
    },
    Failed {
        code: String,
    },
}

impl Record {
    fn new(outcome: &Outcome) -> Option<Self> {
        Some(match outcome {
            Ok(forwarded) => Self::Answered {
                status: forwarded.status.as_u16(),
                content_type: forwarded.content_type.to_str().ok()?.to_owned(),
                body: String::from_utf8(forwarded.body.to_vec()).ok()?,
            },
            Err(error) => Self::Failed {
                code: error.code().to_owned(),
            },
        })
    }

    fn outcome(self) -> Option<Outcome> {
        Some(match self {
            Self::Answered {
                status,
                content_type,
                body,
            } => Ok(Forwarded {
                status: StatusCode::from_u16(status).ok()?,
                content_type: HeaderValue::try_from(content_type).ok()?,
                body: Bytes::from(body),
            }),
            Self::Failed { code } => Err(code.parse().ok()?),
        })
    }
}

/// Every gateway task shares the ledger through Redis. Claiming is one
/// `SET key running NX GET EX window`, so exactly one task runs a ciphertext
/// and the others read its record; an unreachable Redis refuses the request.
pub struct SharedLedger {
    connection: ConnectionManager,
    window_secs: u64,
}

impl SharedLedger {
    fn redis_key(key: Key) -> String {
        format!("{KEY_PREFIX}{}", hex::encode(key.0))
    }

    async fn query<T: redis::FromRedisValue>(&self, command: &redis::Cmd) -> Result<T, ApiError> {
        let mut connection = self.connection.clone();
        let unavailable = |reason: &str| {
            tracing::warn!(reason, "replay ledger unavailable");
            statsd_count!("enclave.replay_guard_unavailable", 1);
            ApiError::ReplayGuardUnavailable
        };
        match tokio::time::timeout(REDIS_TIMEOUT, command.query_async(&mut connection)).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(error)) => Err(unavailable(&error.to_string())),
            Err(_) => Err(unavailable("timed out")),
        }
    }

    async fn claim(&self, key: Key) -> Result<Claim, ApiError> {
        let mut claim = redis::cmd("SET");
        claim
            .arg(Self::redis_key(key))
            .arg(RUNNING)
            .arg("NX")
            .arg("GET")
            .arg("EX")
            .arg(self.window_secs);
        let Some(held) = self.query::<Option<String>>(&claim).await? else {
            return Ok(Claim::New(key));
        };
        if held == RUNNING {
            return Err(ApiError::OperationInProgress);
        }
        let record: Record = serde_json::from_str(&held).map_err(|error| {
            tracing::warn!(%error, "replay record is malformed");
            ApiError::ReplayGuardUnavailable
        })?;
        record
            .outcome()
            .map(Claim::Answered)
            .ok_or(ApiError::ReplayGuardUnavailable)
    }

    async fn record(&self, key: Key, outcome: &Outcome) {
        let Some(record) = Record::new(outcome).and_then(|r| serde_json::to_string(&r).ok()) else {
            tracing::warn!("operation outcome is not recordable");
            return;
        };
        let mut set = redis::cmd("SET");
        set.arg(Self::redis_key(key))
            .arg(record)
            .arg("XX")
            .arg("EX")
            .arg(self.window_secs);
        let _ = self.query::<Option<String>>(&set).await;
    }

    async fn release(&self, key: Key) {
        let mut delete = redis::cmd("DEL");
        delete.arg(Self::redis_key(key));
        let _ = self.query::<u64>(&delete).await;
    }
}

enum Entry {
    Running,
    Answered(Outcome),
}

/// The ledger of one process. Two generations rotate, so an outcome is
/// remembered for one to two windows.
pub struct LocalLedger {
    window: Duration,
    max_entries: usize,
    state: Mutex<Generations>,
}

struct Generations {
    maps: [HashMap<Key, Entry>; 2],
    current: usize,
    rotated_at: Instant,
}

impl Generations {
    fn rotate(&mut self, now: Instant) {
        self.current ^= 1;
        self.maps[self.current].clear();
        self.rotated_at = now;
    }

    fn get_mut(&mut self, key: Key) -> Option<&mut Entry> {
        let [first, second] = &mut self.maps;
        first.get_mut(&key).or_else(|| second.get_mut(&key))
    }
}

impl LocalLedger {
    pub fn new(window: Duration, max_entries: usize) -> Self {
        Self {
            window,
            max_entries,
            state: Mutex::new(Generations {
                maps: [HashMap::new(), HashMap::new()],
                current: 0,
                rotated_at: Instant::now(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Generations> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn claim(&self, key: Key, now: Instant) -> Result<Claim, ApiError> {
        let mut state = self.lock();
        let expired = now.saturating_duration_since(state.rotated_at) >= self.window;
        if expired || state.maps[state.current].len() >= self.max_entries {
            if !expired {
                statsd_count!("enclave.replay_guard_early_rotation", 1);
            }
            state.rotate(now);
        }
        match state.get_mut(key) {
            None => {
                let current = state.current;
                state.maps[current].insert(key, Entry::Running);
                Ok(Claim::New(key))
            }
            Some(Entry::Running) => Err(ApiError::OperationInProgress),
            Some(Entry::Answered(outcome)) => Ok(Claim::Answered(outcome.clone())),
        }
    }

    fn record(&self, key: Key, outcome: &Outcome) {
        if let Some(entry) = self.lock().get_mut(key) {
            *entry = Entry::Answered(outcome.clone());
        }
    }

    fn release(&self, key: Key) {
        for map in &mut self.lock().maps {
            map.remove(&key);
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/replay_isolation.rs"]
mod tests;
