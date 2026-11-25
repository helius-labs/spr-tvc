//! HTTP to the enclave. The mobile wallet can supply its own transport.

use std::io::Read;
use std::time::Duration;

use spr_tvc_wire::error::{ErrorCode, TvcError};

use crate::ClientError;

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
        let failure = if url.ends_with("/v1/ping") || url.ends_with("/v1/decryption/session") {
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
                .map_err(|_| ClientError::InvalidGatekeeperConfig)?;
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

pub(crate) fn discovery_limit() -> usize {
    MAX_DISCOVERY_BYTES
}

pub(crate) fn session_limit() -> usize {
    MAX_DISCOVERY_BYTES * 2 + 512 * 1024
}
