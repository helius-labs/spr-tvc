//! HTTP to the enclave. The mobile wallet can supply its own transport.

use std::io::Read;
use std::time::Duration;

use spr_tvc_wire::error::{ErrorCode, TvcError};

use crate::ClientError;

#[cfg(feature = "local-dev")]
const MAX_DISCOVERY_BYTES: usize = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

pub trait Transport {
    fn get(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>, ClientError>;
    fn post(&self, url: &str, body: &str, max_bytes: usize) -> Result<Vec<u8>, ClientError>;
    fn post_with_api_key(
        &self,
        url: &str,
        api_key: &str,
        body: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ClientError>;
}

pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestTransport {
    pub fn new() -> Result<Self, ClientError> {
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| ClientError::Transport)?;
        Ok(Self { client })
    }
}

impl Transport for ReqwestTransport {
    fn get(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>, ClientError> {
        read(
            self.client
                .get(url)
                .send()
                .map_err(|_| ClientError::Transport)?,
            max_bytes,
            ErrorCode::DiscoveryUntrusted,
        )
    }

    fn post(&self, url: &str, body: &str, max_bytes: usize) -> Result<Vec<u8>, ClientError> {
        self.send(url, body, None, max_bytes)
    }

    fn post_with_api_key(
        &self,
        url: &str,
        api_key: &str,
        body: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ClientError> {
        self.send(url, body, Some(api_key), max_bytes)
    }
}

impl ReqwestTransport {
    fn send(
        &self,
        url: &str,
        body: &str,
        api_key: Option<&str>,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ClientError> {
        let failure = if url.ends_with("/v1/ping") {
            ErrorCode::BootProofUnverified
        } else if url.ends_with("/v1/info") {
            ErrorCode::DiscoveryUntrusted
        } else {
            ErrorCode::TurnkeyEvidenceInvalid
        };
        let mut request = self
            .client
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_owned());
        if let Some(api_key) = api_key {
            let mut header = reqwest::header::HeaderValue::from_str(api_key)
                .map_err(|_| ClientError::InvalidServiceConfig)?;
            header.set_sensitive(true);
            request = request.header("x-api-key", header);
        }
        read(
            request.send().map_err(|_| ClientError::Transport)?,
            max_bytes,
            failure,
        )
    }
}

fn read(
    response: reqwest::blocking::Response,
    max_bytes: usize,
    failure: ErrorCode,
) -> Result<Vec<u8>, ClientError> {
    if !response.status().is_success() {
        if response.status().is_server_error() {
            return Err(ClientError::Transport);
        }
        return Err(TvcError::new(failure).into());
    }
    let limit = u64::try_from(max_bytes).map_err(|_| ClientError::ResponseTooLarge)?;
    let mut bytes = Vec::new();
    response
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ClientError::Transport)?;
    if bytes.len() > max_bytes {
        return Err(ClientError::ResponseTooLarge);
    }
    Ok(bytes)
}

#[cfg(feature = "local-dev")]
pub(crate) fn discovery_limit() -> usize {
    MAX_DISCOVERY_BYTES
}

#[cfg(test)]
mod tests {
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
}
