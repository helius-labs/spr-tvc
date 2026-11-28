//! Transport security tests covering INV-28 (bounded responses, no redirects, API key isolation,
//! HTTP status mapping) and INV-29 (request/body timeouts on stalled peers).

use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::thread;

use super::*;

/// Positive + negative (INV-28): accepts a 200 JSON reply within the byte cap while sending
/// `x-api-key`, and rejects a reply whose body exceeds `max_bytes`.
#[test]
fn posts_with_api_key_within_cap_and_rejects_oversized_response() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        // First request: small valid reply.
        let (mut stream, _) = listener.accept().unwrap();
        let mut req = [0u8; 1024];
        let n = stream.read(&mut req).unwrap();
        let req_text = std::str::from_utf8(&req[..n]).unwrap().to_ascii_lowercase();
        assert!(req_text.contains("x-api-key: test-key"));
        assert!(req_text.contains("content-type: application/json"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 9\r\n\r\n{\"ok\":1}\n",
            )
            .unwrap();

        // Second request: oversized reply (32 bytes vs 8-byte client limit).
        let (mut stream, _) = listener.accept().unwrap();
        let mut req = [0u8; 1024];
        let _ = stream.read(&mut req);
        let body = "a".repeat(32);
        let response = format!(
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let transport = ReqwestTransport::new().unwrap();
    let url = format!("http://{addr}/v1/decryption/operations");

    let ok = transport
        .post_with_api_key(&url, "test-key", "{}", 64)
        .unwrap();
    assert_eq!(ok, b"{\"ok\":1}\n");

    let too_large = transport.post_with_api_key(&url, "test-key", "{}", 8);
    assert!(matches!(too_large, Err(ClientError::ResponseTooLarge)));

    server.join().unwrap();
}

/// Negative (INV-28): refuses HTTP redirects without contacting the redirect target or forwarding
/// `x-api-key`.
#[test]
fn does_not_follow_redirects_or_forward_api_keys() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let target_addr = target.local_addr().unwrap();

    let redirector = TcpListener::bind("127.0.0.1:0").unwrap();
    let redirector_addr = redirector.local_addr().unwrap();
    let redirect_thread = thread::spawn(move || {
        let (mut stream, _) = redirector.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        let response = format!(
            "HTTP/1.1 307 Temporary Redirect\r\nConnection: close\r\nLocation: http://{target_addr}/steal\r\nContent-Length: 0\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let transport = ReqwestTransport::new().unwrap();
    let result = transport.post_with_api_key(
        &format!("http://{redirector_addr}/v1/decryption/operations"),
        "secret-api-key",
        "{}",
        1024,
    );
    assert!(matches!(
        result,
        Err(ClientError::Protocol(ref err)) if err.code == ErrorCode::TurnkeyEvidenceInvalid
    ));
    redirect_thread.join().unwrap();
    assert!(matches!(
        target.accept(),
        Err(ref err) if err.kind() == ErrorKind::WouldBlock
    ));
}

/// Negative (INV-28): maps non-2xx HTTP statuses per route (4xx to protocol errors, 5xx to
/// Transport) and rejects invalid header characters in the API key before connecting.
#[test]
fn maps_http_error_statuses_and_rejects_malformed_api_key_headers() {
    let cases = [
        (
            "/v1/decryption/operations",
            400,
            Some(ErrorCode::TurnkeyEvidenceInvalid),
        ),
        (
            "/v1/decryption/operations",
            429,
            Some(ErrorCode::TurnkeyEvidenceInvalid),
        ),
        ("/v1/ping", 400, Some(ErrorCode::BootProofUnverified)),
        ("/v1/info", 404, Some(ErrorCode::DiscoveryUntrusted)),
        ("/v1/decryption/operations", 503, None),
    ];

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let expected_statuses: Vec<u16> = cases.iter().map(|(_, status, _)| *status).collect();
    let server = thread::spawn(move || {
        for status in expected_statuses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut req = [0u8; 1024];
            let _ = stream.read(&mut req);
            let response =
                format!("HTTP/1.1 {status} Err\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
            stream.write_all(response.as_bytes()).unwrap();
        }
    });

    let transport = ReqwestTransport::new().unwrap();
    for (path, _status, expected_code) in cases {
        let url = format!("http://{addr}{path}");
        let result = transport.post_with_api_key(&url, "test-key", "{}", 1024);
        match expected_code {
            Some(code) => assert!(
                matches!(result, Err(ClientError::Protocol(ref err)) if err.code == code),
                "expected {code:?} for {path}, got {result:?}"
            ),
            None => assert!(
                matches!(result, Err(ClientError::Transport)),
                "expected Transport for 5xx on {path}, got {result:?}"
            ),
        }
    }
    server.join().unwrap();

    // CRLF in API key fails locally without attempting a network connection.
    let crlf_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    crlf_listener.set_nonblocking(true).unwrap();
    let crlf_addr = crlf_listener.local_addr().unwrap();
    let invalid = transport.post_with_api_key(
        &format!("http://{crlf_addr}/v1/decryption/operations"),
        "key\r\nX-Injected: yes",
        "{}",
        1024,
    );
    assert!(matches!(invalid, Err(ClientError::InvalidServiceConfig)));
    assert!(matches!(
        crlf_listener.accept(),
        Err(ref err) if err.kind() == ErrorKind::WouldBlock
    ));
}

/// Negative (INV-28, INV-29): a stalled server that accepts the connection without completing the
/// response times out cleanly with `ClientError::Transport`.
#[test]
fn times_out_on_stalled_headers_and_stalled_bodies() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let server = thread::spawn(move || {
        // First connection: never sends response headers.
        let (stalled_headers, _) = listener.accept().unwrap();
        // Second connection: sends headers promising 64 bytes, then stalls mid-body.
        let (mut stalled_body, _) = listener.accept().unwrap();
        let mut req = [0u8; 1024];
        let _ = stalled_body.read(&mut req);
        let _ = stalled_body
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 64\r\n\r\npart");
        let _ = done_rx.recv();
        drop((stalled_headers, stalled_body));
    });

    let transport = ReqwestTransport::with_timeout(Duration::from_millis(150)).unwrap();
    let url = format!("http://{addr}/v1/decryption/operations");

    assert!(matches!(
        transport.post_with_api_key(&url, "test-key", "{}", 1024),
        Err(ClientError::Transport)
    ));
    assert!(matches!(
        transport.post_with_api_key(&url, "test-key", "{}", 1024),
        Err(ClientError::Transport)
    ));

    let _ = done_tx.send(());
    server.join().unwrap();
}
