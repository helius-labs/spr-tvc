//! Signs the fixed bootstrap derivation message via Turnkey or the local testkit.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use qos_p256::P256Pair;
use turnkey_api_key_stamper::Stamp;
use turnkey_client::generated::external::activity::v1::SignRawPayloadRequest;
use turnkey_client::generated::immutable::{
    activity::v1::{
        intent, result, ActivityStatus, ActivityType, SignRawPayloadIntentV2, SignRawPayloadResult,
    },
    common::v1::{HashFunction, PayloadEncoding},
};
use turnkey_client::generated::services::coordinator::public::v1::{
    ActivityResponse, GetActivityRequest,
};
use turnkey_client::{ActivityResult, TurnkeyClient, TurnkeyClientError};
use zeroize::{Zeroize, Zeroizing};

use crate::turnkey::QosTurnkeyStamper;

/// The Turnkey key a descriptor names. `sign_with` is the wallet's Solana
/// address, which Turnkey accepts as the key selector.
pub(crate) struct WalletKey<'a> {
    pub organization_id: &'a str,
    pub sign_with: &'a str,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CustodyError {
    /// The custodian could not be reached or answered unusably.
    Unavailable,
    /// The custodian declined to sign.
    Declined,
}

pub(crate) struct RawSignature {
    /// The signature over the bootstrap message, which is the wallet's
    /// derivation seed.
    pub signature: Zeroizing<[u8; 64]>,
    /// The Turnkey activity that signed.
    pub activity_id: String,
}

#[async_trait]
pub(crate) trait Custody: Send + Sync {
    async fn sign_raw(
        &self,
        wallet: &WalletKey<'_>,
        payload: &[u8],
        timestamp_ms: u64,
    ) -> Result<RawSignature, CustodyError>;
}

pub(crate) struct TurnkeyCustody {
    quorum: Arc<P256Pair>,
}

impl TurnkeyCustody {
    pub(crate) fn new(quorum: Arc<P256Pair>) -> Self {
        Self { quorum }
    }

    fn client(&self) -> Result<TurnkeyClient<QosTurnkeyStamper>, CustodyError> {
        TurnkeyClient::builder()
            .api_key(QosTurnkeyStamper::new(Arc::clone(&self.quorum)))
            .build()
            .map_err(|_| CustodyError::Unavailable)
    }
}

fn decode_hex(value: &str) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map(Zeroizing::new)
        .map_err(|_| CustodyError::Unavailable)
}

#[async_trait]
impl Custody for TurnkeyCustody {
    async fn sign_raw(
        &self,
        wallet: &WalletKey<'_>,
        payload: &[u8],
        timestamp_ms: u64,
    ) -> Result<RawSignature, CustodyError> {
        let mut activity = sign_with_approval(
            &self.client()?,
            wallet.organization_id,
            timestamp_ms,
            SignRawPayloadIntentV2 {
                sign_with: wallet.sign_with.to_owned(),
                payload: hex::encode(payload),
                encoding: PayloadEncoding::Hexadecimal,
                hash_function: HashFunction::NotApplicable,
            },
        )
        .await?;
        let decoded = (
            decode_hex(&activity.result.r),
            decode_hex(&activity.result.s),
        );
        activity.result.r.zeroize();
        activity.result.s.zeroize();
        let (r, s) = (decoded.0?, decoded.1?);
        if r.len() != 32 || s.len() != 32 {
            return Err(CustodyError::Unavailable);
        }
        let mut signature = Zeroizing::new([0u8; 64]);
        signature[..32].copy_from_slice(&r);
        signature[32..].copy_from_slice(&s);
        Ok(RawSignature {
            signature,
            activity_id: activity.activity_id,
        })
    }
}

/// Poll the original activity: resubmitting would create another approval request.
/// The operation handler enforces the deadline.
async fn sign_with_approval<S: Stamp>(
    client: &TurnkeyClient<S>,
    organization_id: &str,
    timestamp_ms: u64,
    params: SignRawPayloadIntentV2,
) -> Result<ActivityResult<SignRawPayloadResult>, CustodyError> {
    let mut request = SignRawPayloadRequest {
        r#type: "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2".to_owned(),
        timestamp_ms: timestamp_ms.to_string(),
        organization_id: organization_id.to_owned(),
        parameters: Some(params.clone()),
        generate_app_proofs: None,
    };
    let mut permission_retries = 0;
    let mut activity = loop {
        // The SDK's sign_raw_payload resubmits Pending activities. Submit directly
        // so that once an activity exists, all subsequent requests query its id.
        match client
            .process_request::<_, ActivityResponse>(
                &request,
                "/public/v1/submit/sign_raw_payload".to_owned(),
            )
            .await
        {
            Ok(response) => break response.activity.ok_or(CustodyError::Unavailable)?,
            // New grants take time to propagate. Denials are cached, so retry
            // them with a fresh timestamp. Other errors may have created an activity.
            Err(TurnkeyClientError::UnexpectedHttpStatus(403, _)) if permission_retries < 10 => {
                permission_retries += 1;
                tokio::time::sleep(Duration::from_millis(500)).await;
                request.timestamp_ms = client.current_timestamp().to_string();
            }
            Err(_) => return Err(CustodyError::Unavailable),
        }
    };
    let activity_id = activity.id.clone();
    let expected_intent = intent::Inner::SignRawPayloadIntentV2(params);
    loop {
        if activity.id != activity_id
            || activity.organization_id != organization_id
            || activity.r#type != ActivityType::SignRawPayloadV2
            || activity
                .intent
                .as_ref()
                .and_then(|intent| intent.inner.as_ref())
                != Some(&expected_intent)
        {
            return Err(CustodyError::Unavailable);
        }
        match activity.status {
            ActivityStatus::Completed => {
                let Some(result::Inner::SignRawPayloadResult(result)) =
                    activity.result.and_then(|result| result.inner)
                else {
                    return Err(CustodyError::Unavailable);
                };
                return Ok(ActivityResult {
                    result,
                    activity_id,
                    status: activity.status,
                    app_proofs: activity.app_proofs,
                });
            }
            ActivityStatus::ConsensusNeeded | ActivityStatus::Pending => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            ActivityStatus::Rejected | ActivityStatus::Failed => {
                return Err(CustodyError::Declined)
            }
            _ => return Err(CustodyError::Unavailable),
        }
        activity = client
            .get_activity(GetActivityRequest {
                organization_id: organization_id.to_owned(),
                activity_id: activity_id.clone(),
            })
            .await
            .map_err(|_| CustodyError::Unavailable)?
            .activity
            .ok_or(CustodyError::Unavailable)?;
    }
}

#[cfg(test)]
#[path = "../tests/unit/bootstrap_custody.rs"]
mod approval_tests;
