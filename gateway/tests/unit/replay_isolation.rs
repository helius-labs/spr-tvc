//! Gateway local and Redis replay ledger tests (INV-25).

use std::sync::Arc;

use super::*;

fn answer(body: &str) -> Outcome {
    Ok(Forwarded {
        status: StatusCode::OK,
        content_type: HeaderValue::from_static("application/json"),
        body: Bytes::from(body.to_owned()),
    })
}

fn body(claim: Result<Claim, ApiError>) -> Result<String, ApiError> {
    match claim? {
        Claim::Answered(outcome) => {
            outcome.map(|forwarded| String::from_utf8_lossy(&forwarded.body).into_owned())
        }
        Claim::New(_) => Ok("new".to_owned()),
    }
}

const APP: &str = "/v1/decryption";
const OTHER_APP: &str = "/v1/other-service";

fn req(ciphertext: &[u8]) -> EncryptedRequest {
    EncryptedRequest {
        version: 1,
        quorum_key_id: "q".to_owned(),
        quorum_key_epoch: 1,
        ciphertext: ciphertext.to_vec(),
    }
}

/// Exercises one ledger the way two gateway tasks would.
async fn a_resend_gets_the_first_outcome(ledger: &ReplayLedger) {
    let (project, other) = (ProjectId::for_tests("a"), ProjectId::for_tests("b"));
    let first_req = req(b"ciphertext");
    let Ok(Claim::New(key)) = ledger.claim(APP, &project, &first_req).await else {
        panic!("the first claim is new");
    };
    assert_eq!(
        body(ledger.claim(APP, &project, &first_req).await),
        Err(ApiError::OperationInProgress)
    );
    ledger.record(key, &answer("first")).await;
    assert_eq!(
        body(ledger.claim(APP, &project, &first_req).await),
        Ok("first".to_owned())
    );

    // Changing outer envelope routing fields (version, quorum_key_id,
    // quorum_key_epoch) produces distinct keys even for identical ciphertext.
    for variant in [
        EncryptedRequest {
            version: 2,
            ..first_req.clone()
        },
        EncryptedRequest {
            quorum_key_id: "other-quorum".to_owned(),
            ..first_req.clone()
        },
        EncryptedRequest {
            quorum_key_epoch: 2,
            ..first_req.clone()
        },
    ] {
        let Ok(Claim::New(variant_key)) = ledger.claim(APP, &project, &variant).await else {
            panic!("distinct envelope fields must not collide in replay ledger");
        };
        assert_ne!(variant_key, key);
        ledger.release(variant_key).await;
    }

    // Another project's request with the same ciphertext is its own: it
    // neither sees nor takes the first project's entry.
    let Ok(Claim::New(theirs)) = ledger.claim(APP, &other, &first_req).await else {
        panic!("another project's claim is new");
    };
    assert_ne!(theirs, key);
    ledger.record(theirs, &answer("theirs")).await;
    assert_eq!(
        body(ledger.claim(APP, &project, &first_req).await),
        Ok("first".to_owned())
    );
    assert_eq!(
        body(ledger.claim(APP, &other, &first_req).await),
        Ok("theirs".to_owned())
    );

    // The same project and ciphertext on another application is its own:
    // posting it to another application must not return the decryption answer.
    let Ok(Claim::New(cross)) = ledger.claim(OTHER_APP, &project, &first_req).await else {
        panic!("another application's claim is new");
    };
    assert_ne!(cross, key);
    ledger.record(cross, &answer("decryption")).await;
    assert_eq!(
        body(ledger.claim(APP, &project, &first_req).await),
        Ok("first".to_owned())
    );
    assert_eq!(
        body(ledger.claim(OTHER_APP, &project, &first_req).await),
        Ok("decryption".to_owned())
    );

    let failed_req = req(b"failed");
    let Ok(Claim::New(failed)) = ledger.claim(APP, &project, &failed_req).await else {
        panic!("the first claim is new");
    };
    ledger
        .record(failed, &Err(ApiError::EnclaveUnavailable))
        .await;
    assert_eq!(
        body(ledger.claim(APP, &project, &failed_req).await),
        Err(ApiError::EnclaveUnavailable)
    );

    let released_req = req(b"released");
    let Ok(Claim::New(released)) = ledger.claim(APP, &project, &released_req).await else {
        panic!("the first claim is new");
    };
    ledger.release(released).await;
    assert_eq!(
        body(ledger.claim(APP, &project, &released_req).await),
        Ok("new".to_owned())
    );

    // An answer at the cap is kept; a larger one releases its claim.
    let largest = "x".repeat(MAX_KEPT_ANSWER_BYTES);
    let largest_req = req(b"largest");
    let Ok(Claim::New(kept)) = ledger.claim(APP, &project, &largest_req).await else {
        panic!("the first claim is new");
    };
    ledger.record(kept, &answer(&largest)).await;
    assert_eq!(
        body(ledger.claim(APP, &project, &largest_req).await),
        Ok(largest)
    );
    let too_large_req = req(b"too large");
    let Ok(Claim::New(dropped)) = ledger.claim(APP, &project, &too_large_req).await else {
        panic!("the first claim is new");
    };
    ledger
        .record(dropped, &answer(&"x".repeat(MAX_KEPT_ANSWER_BYTES + 1)))
        .await;
    assert_eq!(
        body(ledger.claim(APP, &project, &too_large_req).await),
        Ok("new".to_owned())
    );
}

#[tokio::test]
async fn a_local_ledger_returns_the_first_outcome_to_a_resend() {
    crate::metrics::init_for_tests();
    let ledger = ReplayLedger::Local(LocalLedger::new(Duration::from_secs(60), 16));
    a_resend_gets_the_first_outcome(&ledger).await;
}

#[tokio::test]
async fn a_shared_ledger_returns_the_first_outcome_to_a_resend() {
    crate::metrics::init_for_tests();
    let url = fake_redis(true).await;
    a_resend_gets_the_first_outcome(&shared(&url).await).await;
}

#[test]
fn a_local_ledger_remembers_across_one_rotation_then_forgets() {
    crate::metrics::init_for_tests();
    let ledger = LocalLedger::new(Duration::from_secs(60), 16);
    let now = Instant::now();
    let key = Key([1; 32]);
    assert!(matches!(ledger.claim(key, now), Ok(Claim::New(_))));
    assert!(matches!(
        ledger.claim(key, now + Duration::from_secs(61)),
        Err(ApiError::OperationInProgress)
    ));
    assert!(matches!(
        ledger.claim(Key([2; 32]), now + Duration::from_secs(122)),
        Ok(Claim::New(_))
    ));
    assert!(matches!(
        ledger.claim(key, now + Duration::from_secs(123)),
        Ok(Claim::New(_))
    ));
}

#[tokio::test]
async fn an_unresponsive_redis_refuses_the_request() {
    crate::metrics::init_for_tests();
    let ledger = shared(&fake_redis(false).await).await;
    assert_eq!(
        body(
            ledger
                .claim(APP, &ProjectId::for_tests("a"), &req(b"ciphertext"))
                .await
        ),
        Err(ApiError::ReplayGuardUnavailable)
    );
}

async fn shared(url: &str) -> ReplayLedger {
    ReplayLedger::connect(Duration::from_secs(360), 16, Some(url))
        .await
        .expect("the shared ledger connects")
}

/// A Redis stand-in on loopback that keeps `SET` (with `NX`, `XX` and
/// `GET`), `DEL` and nothing else in memory, ignoring expiry. With
/// `answering` false it never answers a `SET`.
async fn fake_redis(answering: bool) -> String {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fake redis binds");
    let addr = listener.local_addr().expect("fake redis has an address");
    let keys = Arc::new(Mutex::new(HashMap::<String, String>::new()));
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve_fake_redis(stream, Arc::clone(&keys), answering));
        }
    });
    format!("redis://{addr}/2")
}

fn bulk(value: Option<&String>) -> String {
    value.map_or_else(
        || "$-1\r\n".to_owned(),
        |v| format!("${}\r\n{v}\r\n", v.len()),
    )
}

async fn serve_fake_redis(
    stream: tokio::net::TcpStream,
    keys: Arc<Mutex<HashMap<String, String>>>,
    answering: bool,
) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
            return;
        }
        let count: usize = line.trim().trim_start_matches('*').parse().unwrap_or(0);
        let mut args = Vec::with_capacity(count);
        for _ in 0..count {
            line.clear();
            let _ = reader.read_line(&mut line).await;
            let len: usize = line.trim().trim_start_matches('$').parse().unwrap_or(0);
            let mut arg = vec![0u8; len + 2];
            let _ = reader.read_exact(&mut arg).await;
            args.push(String::from_utf8_lossy(&arg[..len]).into_owned());
        }
        let has = |flag: &str| args.iter().any(|arg| arg.eq_ignore_ascii_case(flag));
        let name = args.first().map(|name| name.to_ascii_uppercase());
        let reply = match (name.as_deref(), args.get(1), args.get(2)) {
            (Some("SET"), _, _) if !answering => continue,
            (Some("SET"), Some(key), Some(value)) => {
                let mut keys = keys.lock().unwrap_or_else(PoisonError::into_inner);
                let held = keys.get(key).cloned();
                let write = (!has("NX") || held.is_none()) && (!has("XX") || held.is_some());
                if write {
                    keys.insert(key.clone(), value.clone());
                }
                match (has("GET"), write) {
                    (true, _) => bulk(held.as_ref()),
                    (false, true) => "+OK\r\n".to_owned(),
                    (false, false) => "$-1\r\n".to_owned(),
                }
            }
            (Some("DEL"), Some(key), _) => {
                let removed = keys
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(key);
                format!(":{}\r\n", u8::from(removed.is_some()))
            }
            _ => "+OK\r\n".to_owned(),
        };
        if write.write_all(reply.as_bytes()).await.is_err() {
            return;
        }
    }
}
