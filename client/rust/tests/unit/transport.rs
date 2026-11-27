use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use super::*;

#[test]
fn does_not_follow_redirects_or_forward_api_keys() {
    let target_hit = Arc::new(AtomicBool::new(false));
    let target_hit_thread = Arc::clone(&target_hit);
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_addr = target.local_addr().unwrap();
    let _target_thread = thread::spawn(move || {
        if let Ok((mut stream, _)) = target.accept() {
            target_hit_thread.store(true, Ordering::SeqCst);
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
        }
    });

    let redirector = TcpListener::bind("127.0.0.1:0").unwrap();
    let redirector_addr = redirector.local_addr().unwrap();
    let redirect_thread = thread::spawn(move || {
        let (mut stream, _) = redirector.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        let response = format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{target_addr}/steal\r\nContent-Length: 0\r\n\r\n"
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
    assert!(result.is_err());
    redirect_thread.join().unwrap();
    assert!(!target_hit.load(Ordering::SeqCst));
}
