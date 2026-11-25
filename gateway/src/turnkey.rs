use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use axum::http::StatusCode;
use bytes::Bytes;
use cadence_macros::statsd_count;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, SemaphorePermit, watch};
use turnkey_client::generated::services::coordinator::public::v1::GetBootProofRequest;
use turnkey_client::{TurnkeyClient, TurnkeyClientError, TurnkeyP256ApiKey};

use crate::config::{TurnkeyApiKey, TurnkeyConfig};
use crate::error::ApiError;
use crate::limits::InFlightLimiter;
use crate::project::ProjectId;

const TURNKEY_TIMEOUT: Duration = Duration::from_secs(15);
/// Both Turnkey keys are shared by every project, so their call rate is too.
const MAX_CONCURRENT_TURNKEY_CALLS: usize = 32;
/// One project's share of those calls, so no project can take them all.
const MAX_CONCURRENT_TURNKEY_CALLS_PER_PROJECT: u32 = 8;
const BOOT_PROOF_CACHE_CAPACITY: usize = 256;
/// A replica's ephemeral key, which signs its answers and names its Boot
/// Proof: 130 bytes, lowercase hex.
const EPHEMERAL_KEY_HEX_LEN: usize = 260;
const TURNKEY_PRIVATE_KEY_HEX_LEN: usize = 64;
const TURNKEY_PUBLIC_KEY_HEX_LEN: usize = 66;

/// Which limits a Turnkey call counts against.
#[derive(Debug, Clone, Copy)]
pub enum CallShare<'a> {
    /// The project's share and the shared bound: a call before any work.
    Project(&'a ProjectId),
    /// The shared bound only: a lookup that completes work the enclave
    /// already did, which the project's share must not waste.
    Shared,
}

/// One Boot Proof lookup in flight: what it answered, once it has.
type BootProofFlight = watch::Receiver<Option<Result<Bytes, ApiError>>>;

pub struct Turnkey {
    tvc_organization_id: String,
    boot_proofs: TurnkeyClient<TurnkeyP256ApiKey>,
    boot_proof_cache: Mutex<HashMap<String, Bytes>>,
    /// At most one Turnkey lookup per ephemeral key at a time; concurrent
    /// callers for the same key share its answer.
    boot_proof_flights: Mutex<HashMap<String, BootProofFlight>>,
    calls: Semaphore,
    project_calls: InFlightLimiter,
}

/// One Turnkey call's slots: the project's own, unless the call is exempt
/// from its share, and a shared one.
type CallPermit<'a> = (Option<OwnedSemaphorePermit>, SemaphorePermit<'a>);

impl Turnkey {
    pub fn new(config: &TurnkeyConfig) -> anyhow::Result<Self> {
        Ok(Self {
            tvc_organization_id: config.tvc_organization_id.clone(),
            boot_proofs: client(
                &config.api_base_url,
                "boot_proof_api_key",
                &config.boot_proof_api_key,
            )?,
            boot_proof_cache: Mutex::new(HashMap::new()),
            boot_proof_flights: Mutex::new(HashMap::new()),
            calls: Semaphore::new(MAX_CONCURRENT_TURNKEY_CALLS),
            project_calls: project_calls(),
        })
    }

    /// The Boot Proof JSON for the replica whose ephemeral key is
    /// `ephemeral_key`, counted against `share`. A replica's proof never
    /// changes, so it is cached, and concurrent lookups of one key, such as a
    /// burst after a deploy, make one Turnkey call and share its answer.
    pub async fn boot_proof(
        &self,
        ephemeral_key: &str,
        share: CallShare<'_>,
    ) -> Result<Bytes, ApiError> {
        if !is_lower_hex(ephemeral_key, EPHEMERAL_KEY_HEX_LEN) {
            return Err(ApiError::InvalidEnclaveAnswer);
        }
        loop {
            if let Some(cached) = self.cached_boot_proof(ephemeral_key) {
                statsd_count!("boot_proof.cache_hit", 1);
                return Ok(cached);
            }
            if let Some(mut flight) = self.boot_proof_flight(ephemeral_key) {
                statsd_count!("boot_proof.shared_lookup", 1);
                // An error: the caller looking it up left before Turnkey
                // answered, so look again.
                if let Ok(answer) = flight.wait_for(Option::is_some).await
                    && let Some(answer) = answer.as_ref()
                {
                    return answer.clone();
                }
                continue;
            }
            // A refused slot is this caller's own answer, never shared.
            let _call = self.call_permit(share)?;
            let (answer, flight) = watch::channel(None);
            {
                let mut flights = self
                    .boot_proof_flights
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if flights.contains_key(ephemeral_key) {
                    continue;
                }
                flights.insert(ephemeral_key.to_owned(), flight.clone());
            }
            let _landed = FlightLanding {
                flights: &self.boot_proof_flights,
                ephemeral_key,
                flight,
            };
            let looked_up = self.fetch_boot_proof(ephemeral_key).await;
            if let Ok(body) = &looked_up {
                self.cache_boot_proof(ephemeral_key, body);
            }
            answer.send_replace(Some(looked_up.clone()));
            return looked_up;
        }
    }

    fn boot_proof_flight(&self, ephemeral_key: &str) -> Option<BootProofFlight> {
        self.boot_proof_flights
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(ephemeral_key)
            .cloned()
    }

    async fn fetch_boot_proof(&self, ephemeral_key: &str) -> Result<Bytes, ApiError> {
        let response = self
            .boot_proofs
            .get_boot_proof(GetBootProofRequest {
                organization_id: self.tvc_organization_id.clone(),
                ephemeral_key: ephemeral_key.to_owned(),
            })
            .await
            .map_err(|error| {
                turnkey_failure("get_boot_proof", &error, ApiError::BootProofUnavailable)
            })?;
        let boot_proof = response.boot_proof.ok_or(ApiError::BootProofUnavailable)?;
        let body = serde_json::to_vec(&boot_proof).map_err(|error| {
            tracing::error!(%error, "boot proof did not serialize");
            ApiError::BootProofUnavailable
        })?;
        Ok(Bytes::from(body))
    }

    /// Slots for one call: one of the project's own unless `share` exempts
    /// it, then one of the shared ones. Neither waits.
    fn call_permit(&self, share: CallShare<'_>) -> Result<CallPermit<'_>, ApiError> {
        let own = match share {
            CallShare::Project(project) => Some(self.project_calls.try_acquire(project)?),
            CallShare::Shared => None,
        };
        let shared = self.calls.try_acquire().map_err(|_| {
            statsd_count!("turnkey.concurrency_rejected", 1);
            ApiError::TooManyInFlight
        })?;
        Ok((own, shared))
    }

    fn cached_boot_proof(&self, ephemeral_key: &str) -> Option<Bytes> {
        self.boot_proof_cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(ephemeral_key)
            .cloned()
    }

    fn cache_boot_proof(&self, ephemeral_key: &str, body: &Bytes) {
        let mut cache = self
            .boot_proof_cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= BOOT_PROOF_CACHE_CAPACITY {
            cache.clear();
        }
        cache.insert(ephemeral_key.to_owned(), body.clone());
    }
}

/// Takes a finished or abandoned lookup out of the flights, so the next
/// caller looks up again or reads the cache.
struct FlightLanding<'a> {
    flights: &'a Mutex<HashMap<String, BootProofFlight>>,
    ephemeral_key: &'a str,
    flight: BootProofFlight,
}

impl Drop for FlightLanding<'_> {
    fn drop(&mut self) {
        let mut flights = self.flights.lock().unwrap_or_else(PoisonError::into_inner);
        if flights
            .get(self.ephemeral_key)
            .is_some_and(|flight| flight.same_channel(&self.flight))
        {
            flights.remove(self.ephemeral_key);
        }
    }
}

fn project_calls() -> InFlightLimiter {
    InFlightLimiter::new(
        MAX_CONCURRENT_TURNKEY_CALLS_PER_PROJECT,
        "turnkey.project_concurrency_rejected",
    )
}

/// `name` identifies the key in errors. The key is checked for shape first:
/// `TurnkeyP256ApiKey` panics on a private key of the wrong length.
fn client(
    base_url: &str,
    name: &str,
    key: &TurnkeyApiKey,
) -> anyhow::Result<TurnkeyClient<TurnkeyP256ApiKey>> {
    anyhow::ensure!(
        is_lower_or_upper_hex(&key.private_key, TURNKEY_PRIVATE_KEY_HEX_LEN),
        "turnkey.{name}.private_key must be 32 bytes of hex"
    );
    anyhow::ensure!(
        is_lower_or_upper_hex(&key.public_key, TURNKEY_PUBLIC_KEY_HEX_LEN),
        "turnkey.{name}.public_key must be a 33-byte compressed P-256 key in hex"
    );
    let api_key = TurnkeyP256ApiKey::from_strings(&key.private_key, Some(&key.public_key))
        .map_err(|error| anyhow::anyhow!("turnkey.{name} is not a valid key pair: {error}"))?;
    Ok(TurnkeyClient::builder()
        .api_key(api_key)
        .base_url(base_url)
        .timeout(TURNKEY_TIMEOUT)
        .build()?)
}

/// A 400, 403 or 404 is the caller's claim failing: `rejected` for the call.
/// A 401 is this gateway's key, a 429 Turnkey's limit, and anything else an
/// outage; all three are 424s.
fn turnkey_failure(call: &'static str, error: &TurnkeyClientError, rejected: ApiError) -> ApiError {
    let status = if let TurnkeyClientError::UnexpectedHttpStatus(status, _) = error {
        Some(*status)
    } else {
        None
    };
    let mapped = turnkey_status(status, rejected);
    if mapped.status() == StatusCode::FAILED_DEPENDENCY {
        let code = mapped.code();
        tracing::warn!(call, code, error = %error, "turnkey call failed");
        statsd_count!("turnkey.failed", 1, "call" => call, "code" => code);
    } else {
        statsd_count!("turnkey.rejected", 1, "call" => call);
    }
    mapped
}

const fn turnkey_status(status: Option<u16>, rejected: ApiError) -> ApiError {
    match status {
        Some(400 | 403 | 404) => rejected,
        Some(401) => ApiError::TurnkeyUnauthorized,
        Some(429) => ApiError::TurnkeyRateLimited,
        Some(_) | None => ApiError::TurnkeyUnavailable,
    }
}

#[inline]
fn is_lower_or_upper_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[inline]
fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
#[path = "../tests/unit/turnkey_boundary.rs"]
mod tests;
