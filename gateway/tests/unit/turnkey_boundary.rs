//! Gateway Turnkey P-256 key validation, burst coalescing, and per-project quota tests (INV-26).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

#[test]
fn turnkey_statuses_split_between_the_callers_claim_and_upstream() {
    assert_eq!(
        turnkey_status(Some(403), ApiError::BootProofUnavailable),
        ApiError::BootProofUnavailable
    );
    assert_eq!(
        turnkey_status(Some(404), ApiError::BootProofUnavailable),
        ApiError::BootProofUnavailable
    );
    assert_eq!(
        turnkey_status(Some(401), ApiError::BootProofUnavailable),
        ApiError::TurnkeyUnauthorized
    );
    assert_eq!(
        turnkey_status(Some(429), ApiError::BootProofUnavailable),
        ApiError::TurnkeyRateLimited
    );
    assert_eq!(
        turnkey_status(Some(503), ApiError::BootProofUnavailable),
        ApiError::TurnkeyUnavailable
    );
    assert_eq!(
        turnkey_status(None, ApiError::BootProofUnavailable),
        ApiError::TurnkeyUnavailable
    );
}

fn turnkey_config(private_key: &str, public_key: &str) -> TurnkeyConfig {
    let key = TurnkeyApiKey {
        private_key: private_key.to_owned(),
        public_key: public_key.to_owned(),
    };
    TurnkeyConfig {
        api_base_url: "http://127.0.0.1:9".to_owned(),
        tvc_organization_id: "00000000-0000-4000-8000-000000000001".to_owned(),
        boot_proof_api_key: key,
    }
}

#[test]
fn a_missing_or_malformed_turnkey_key_is_a_startup_error_not_a_panic() {
    for (private_key, public_key) in [
        ("", ""),
        ("08", "02"),
        (&*"zz".repeat(32), &*"02".repeat(33)),
        (&*"08".repeat(32), ""),
    ] {
        let error = Turnkey::new(&turnkey_config(private_key, public_key))
            .err()
            .expect("a malformed key was accepted");
        assert!(
            error.to_string().starts_with("turnkey.boot_proof_api_key"),
            "{error}"
        );
    }
}

#[test]
fn a_key_pair_that_does_not_match_is_refused() {
    let error = Turnkey::new(&turnkey_config(&"08".repeat(32), &"02".repeat(33)))
        .err()
        .expect("a mismatched key pair was accepted");
    assert!(
        error.to_string().contains("not a valid key pair"),
        "{error}"
    );
}

#[test]
fn one_project_cannot_take_every_turnkey_call() {
    crate::metrics::init_for_tests();
    let turnkey = Turnkey::for_tests("http://127.0.0.1:9");
    let busy = ProjectId::for_tests("busy");
    let held: Vec<_> = (0..MAX_CONCURRENT_TURNKEY_CALLS_PER_PROJECT)
        .map(|_| {
            turnkey
                .call_permit(CallShare::Project(&busy))
                .expect("within the project's share")
        })
        .collect();
    assert_eq!(
        turnkey.call_permit(CallShare::Project(&busy)).err(),
        Some(ApiError::TooManyInFlight)
    );
    // The other projects share the rest, and only the rest.
    let rest = MAX_CONCURRENT_TURNKEY_CALLS - held.len();
    let others: Vec<_> = (0..rest)
        .map(|index| {
            let project = ProjectId::for_tests(&format!("other-{index}"));
            turnkey
                .call_permit(CallShare::Project(&project))
                .expect("a shared slot")
        })
        .collect();
    let late = ProjectId::for_tests("late");
    assert_eq!(
        turnkey.call_permit(CallShare::Project(&late)).err(),
        Some(ApiError::TooManyInFlight)
    );
    // An exempt call still counts against the shared bound.
    assert_eq!(
        turnkey.call_permit(CallShare::Shared).err(),
        Some(ApiError::TooManyInFlight)
    );
    drop(others);
    assert!(turnkey.call_permit(CallShare::Project(&late)).is_ok());
    drop(held);
    assert!(turnkey.call_permit(CallShare::Project(&busy)).is_ok());
}

/// A Turnkey that answers each Boot Proof lookup after `delay`, with the
/// next of `statuses` (200 once they run out), and counts the lookups.
async fn mock_turnkey(
    delay: Duration,
    statuses: Vec<StatusCode>,
) -> (Arc<Turnkey>, Arc<AtomicUsize>) {
    use axum::extract::State;
    use axum::routing::post;

    type Mock = (Arc<AtomicUsize>, Arc<Mutex<Vec<StatusCode>>>, Duration);
    async fn lookup(
        State((calls, statuses, delay)): State<Mock>,
        body: Bytes,
    ) -> (StatusCode, axum::Json<serde_json::Value>) {
        calls.fetch_add(1, Ordering::SeqCst);
        let request: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        tokio::time::sleep(delay).await;
        let status = {
            let mut statuses = statuses.lock().unwrap_or_else(PoisonError::into_inner);
            if statuses.is_empty() {
                StatusCode::OK
            } else {
                statuses.remove(0)
            }
        };
        let body = serde_json::json!({ "bootProof": {
            "ephemeralPublicKeyHex": request["ephemeralKey"],
            "awsAttestationDocB64": "",
            "qosManifestB64": "",
            "qosManifestEnvelopeB64": "",
            "deploymentLabel": "test",
            "enclaveApp": "test",
            "owner": "test",
        }});
        (status, axum::Json(body))
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let state: Mock = (Arc::clone(&calls), Arc::new(Mutex::new(statuses)), delay);
    let router = axum::Router::new()
        .route("/public/v1/query/get_boot_proof", post(lookup))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let url = format!("http://{}", listener.local_addr().expect("an address"));
    tokio::spawn(async move { axum::serve(listener, router).await });
    (Arc::new(Turnkey::for_tests(&url)), calls)
}

/// A replica's ephemeral key: 130 bytes, lowercase hex.
fn key() -> String {
    "04".repeat(130)
}

/// Every caller's answer when `count` of them look [`key`] up at once.
async fn burst(turnkey: &Arc<Turnkey>, count: usize) -> Vec<Result<Bytes, ApiError>> {
    let mut lookups = tokio::task::JoinSet::new();
    for _ in 0..count {
        let turnkey = Arc::clone(turnkey);
        lookups.spawn(async move { turnkey.boot_proof(&key(), CallShare::Shared).await });
    }
    lookups.join_all().await
}

#[tokio::test]
async fn a_burst_of_lookups_for_one_replica_makes_one_turnkey_call() {
    crate::metrics::init_for_tests();
    let (turnkey, calls) = mock_turnkey(Duration::from_millis(200), Vec::new()).await;
    let answers = burst(&turnkey, 16).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let first = answers[0].clone().expect("the lookup answered");
    assert!(answers.iter().all(|answer| answer.as_ref() == Ok(&first)));
    // Then the cache answers.
    assert_eq!(
        turnkey.boot_proof(&key(), CallShare::Shared).await,
        Ok(first)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_failed_lookup_answers_its_burst_once_and_the_next_caller_looks_again() {
    crate::metrics::init_for_tests();
    let (turnkey, calls) = mock_turnkey(
        Duration::from_millis(200),
        vec![StatusCode::SERVICE_UNAVAILABLE],
    )
    .await;
    let answers = burst(&turnkey, 8).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        answers
            .iter()
            .all(|answer| answer == &Err(ApiError::TurnkeyUnavailable)),
        "{answers:?}"
    );
    assert!(turnkey.boot_proof(&key(), CallShare::Shared).await.is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_caller_waiting_on_an_abandoned_lookup_looks_up_itself() {
    crate::metrics::init_for_tests();
    let (turnkey, calls) = mock_turnkey(Duration::from_millis(300), Vec::new()).await;
    let first = {
        let turnkey = Arc::clone(&turnkey);
        tokio::spawn(async move { turnkey.boot_proof(&key(), CallShare::Shared).await })
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the first lookup reached Turnkey");
    let second = {
        let turnkey = Arc::clone(&turnkey);
        tokio::spawn(async move { turnkey.boot_proof(&key(), CallShare::Shared).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    first.abort();
    assert!(second.await.expect("the lookup ran").is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_lookup_after_the_enclave_answered_takes_no_slot_of_the_projects_share() {
    crate::metrics::init_for_tests();
    let turnkey = Turnkey::for_tests("http://127.0.0.1:9");
    let busy = ProjectId::for_tests("busy");
    let _held: Vec<_> = (0..MAX_CONCURRENT_TURNKEY_CALLS_PER_PROJECT)
        .map(|_| {
            turnkey
                .call_permit(CallShare::Project(&busy))
                .expect("within the project's share")
        })
        .collect();
    assert_eq!(
        turnkey.boot_proof(&key(), CallShare::Project(&busy)).await,
        Err(ApiError::TooManyInFlight)
    );
    // It reaches Turnkey, which is not there.
    assert_eq!(
        turnkey.boot_proof(&key(), CallShare::Shared).await,
        Err(ApiError::TurnkeyUnavailable)
    );
}

#[test]
fn ephemeral_key_must_be_lower_hex_of_the_exact_length() {
    assert!(is_lower_hex(&"ab".repeat(130), EPHEMERAL_KEY_HEX_LEN));
    assert!(!is_lower_hex(&"AB".repeat(130), EPHEMERAL_KEY_HEX_LEN));
    assert!(!is_lower_hex(&"ab".repeat(129), EPHEMERAL_KEY_HEX_LEN));
}

impl Turnkey {
    pub(crate) fn for_tests(api_base_url: &str) -> Self {
        let key = || {
            TurnkeyP256ApiKey::from_strings("08".repeat(32), None)
                .expect("test turnkey key is invalid")
        };
        let build = || {
            TurnkeyClient::builder()
                .api_key(key())
                .base_url(api_base_url)
                .build()
                .expect("test turnkey client did not build")
        };
        Self {
            tvc_organization_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            boot_proofs: build(),
            boot_proof_cache: Mutex::new(HashMap::new()),
            boot_proof_flights: Mutex::new(HashMap::new()),
            calls: Semaphore::new(MAX_CONCURRENT_TURNKEY_CALLS),
            project_calls: project_calls(),
        }
    }
}
