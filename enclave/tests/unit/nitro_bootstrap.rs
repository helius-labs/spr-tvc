use crate::{
    custody::tests::{fixture, DOMAIN},
    kms_recipient::tests::envelope,
};

use super::*;

fn key() -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
}

fn frame(envelopes: &[(u8, &[u8])]) -> Vec<u8> {
    let mut frame = Vec::new();
    for (slot, envelope) in envelopes {
        frame.push(*slot);
        frame.extend(u16::try_from(envelope.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(envelope);
    }
    frame
}

#[test]
fn bootstrap_requires_three_distinct_valid_shares_for_this_boot_recipient() {
    let seed = NoteSeed(Zeroizing::new([0x88; 32]));
    let (custody, shares) = fixture(1, &seed);
    let recipient = key();
    let wrong_recipient = key();
    let [first, second, third] = [0, 2, 5].map(|index| envelope(&recipient, &shares[index]));
    let a = (1, first.as_slice());
    let b = (3, second.as_slice());
    let c = (6, third.as_slice());
    let wrong = envelope(&wrong_recipient, &shares[5]);
    let short = envelope(&recipient, &[0; 32]);
    let large = vec![0; MAX_CMS_BYTES + 1];
    for envelopes in [
        vec![a, b],
        vec![a, a, b],
        vec![a, b, (6, &wrong)],
        vec![a, b, (6, &short)],
        vec![a, b, (6, &large)],
        vec![a, b, (6, &third[..third.len() - 1])],
        vec![a, b, (4, &third)],
        vec![a, b, (0, &third)],
        vec![a, b, (7, &third)],
        vec![a, b, c, c, c, c, c],
    ] {
        let bytes = frame(&envelopes);
        assert!(open_shares(&recipient, &bytes, &DOMAIN, &custody).is_none());
    }
    assert!(open_shares(&recipient, &[0], &DOMAIN, &custody).is_none());
    assert!(open_shares(&recipient, &[1, 0xff, 0xff], &DOMAIN, &custody).is_none());
    let bytes = frame(&[a, b, (6, &wrong), (4, &third), c]);
    let (restored, slots) = open_shares(&recipient, &bytes, &DOMAIN, &custody).unwrap();
    assert_eq!(*restored.0, *seed.0);
    assert_eq!(slots, [1, 3, 6]);
}

#[tokio::test]
async fn bootstrap_acknowledges_only_the_slots_used_to_restore_the_seed() {
    let seed = NoteSeed(Zeroizing::new([0x88; 32]));
    let (custody, shares) = fixture(1, &seed);
    let private = key();
    let envelopes = [0, 2, 4, 5].map(|index| envelope(&private, &shares[index]));
    let (sender, restored) = oneshot::channel();
    let state = Arc::new(Bootstrap {
        recipient: Mutex::new(Some(Recipient { private, sender })),
        domain: DOMAIN,
        custody,
        deadline: Instant::now() + BOOTSTRAP_TIMEOUT,
    });
    let worker = Arc::new(Semaphore::new(1));
    let permit = worker.acquire().await.unwrap();
    assert_eq!(
        accept_shares(
            State(state.clone()),
            Extension(worker.clone()),
            Bytes::new()
        )
        .await
        .unwrap_err(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        kms_attestation(State(state.clone()), Extension(worker.clone()))
            .await
            .unwrap_err(),
        StatusCode::TOO_MANY_REQUESTS
    );
    drop(permit);
    let a = (1, envelopes[0].as_slice());
    let b = (3, envelopes[1].as_slice());
    let c = (5, envelopes[2].as_slice());
    let d = (6, envelopes[3].as_slice());
    let invalid = Bytes::from(frame(&[a, b, (6, &envelopes[2])]));
    assert_eq!(
        accept_shares(State(state.clone()), Extension(worker.clone()), invalid)
            .await
            .unwrap_err(),
        StatusCode::BAD_REQUEST
    );
    let valid = Bytes::from(frame(&[a, b, c, d]));
    let (_, slots) = accept_shares(
        State(state.clone()),
        Extension(worker.clone()),
        valid.clone(),
    )
    .await
    .unwrap();
    assert_eq!(slots, [1, 3, 5]);
    let (restored, actual_slots) = restored.await.unwrap();
    assert_eq!(*restored.0, *seed.0);
    assert_eq!(actual_slots, [1, 3, 5]);
    assert_eq!(
        accept_shares(State(state), Extension(worker), valid)
            .await
            .unwrap_err(),
        StatusCode::GONE
    );
}

#[tokio::test(start_paused = true)]
async fn bootstrap_refuses_to_commit_a_recovered_seed_at_the_deadline() {
    let seed = NoteSeed(Zeroizing::new([0x88; 32]));
    let (custody, _) = fixture(1, &seed);
    let (sender, mut receiver) = oneshot::channel();
    let state = Bootstrap {
        recipient: Mutex::new(Some(Recipient {
            private: key(),
            sender,
        })),
        domain: DOMAIN,
        custody,
        deadline: Instant::now() + BOOTSTRAP_TIMEOUT,
    };
    assert!(state.private_key().is_ok());
    tokio::time::advance(BOOTSTRAP_TIMEOUT).await;
    assert_eq!(state.private_key().err(), Some(StatusCode::GONE));
    assert_eq!(state.complete((seed, [1, 2, 3])), Err(StatusCode::GONE));
    assert!(matches!(
        receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn verified_bootstrap_consumes_the_recipient_before_its_worker_is_released() {
    use std::task::{Context, Waker};

    let seed = NoteSeed(Zeroizing::new([0x88; 32]));
    let (custody, shares) = fixture(1, &seed);
    let private = key();
    let [first, second, third] = [0, 2, 4].map(|index| envelope(&private, &shares[index]));
    let (sender, mut restored) = oneshot::channel();
    let state = Arc::new(Bootstrap {
        recipient: Mutex::new(Some(Recipient { private, sender })),
        domain: DOMAIN,
        custody,
        deadline: Instant::now() + BOOTSTRAP_TIMEOUT,
    });
    let worker = Arc::new(Semaphore::new(1));
    let mut request = Box::pin(accept_shares(
        State(state.clone()),
        Extension(worker.clone()),
        Bytes::from(frame(&[(1, &first), (3, &second), (5, &third)])),
    ));
    {
        // Dispatch the worker, then let the HTTP caller disappear before it can send a reply.
        let _pending_recipient = state.recipient.lock().unwrap();
        assert!(request
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    drop(request);
    let _permit = tokio::time::timeout(Duration::from_secs(5), worker.acquire())
        .await
        .unwrap()
        .unwrap();
    let (loaded, slots) = restored.try_recv().unwrap();
    assert_eq!(*loaded.0, *seed.0);
    assert_eq!(slots, [1, 3, 5]);
    assert_eq!(state.private_key().err(), Some(StatusCode::GONE));
}
