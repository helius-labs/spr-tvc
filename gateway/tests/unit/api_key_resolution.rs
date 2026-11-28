//! Gateway API-key lookup and negative caching tests (INV-23).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Json};
use axum::routing::get;

use super::*;

const KEY: &str = "0b4a3a9e-5f7e-4b4f-9c1e-0d9f2a1b3c4d";
const FAILING_KEY: &str = "5e5e5e5e-5f7e-4b4f-9c1e-0d9f2a1b3c4d";
const NO_WAAS_KEY: &str = "7a7a7a7a-5f7e-4b4f-9c1e-0d9f2a1b3c4d";

/// A dev-api that knows `KEY` as `project-a`, refuses `NO_WAAS_KEY`'s
/// project the WaaS add-on, fails for `FAILING_KEY`, and counts its lookups.
async fn dev_api() -> (String, Arc<AtomicUsize>) {
    crate::metrics::init_for_tests();
    let lookups = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&lookups);
    let app = Router::new().route(
        "/v0/waas/config",
        get(move |headers: HeaderMap| {
            counted.fetch_add(1, Ordering::SeqCst);
            async move {
                match headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
                    Some(KEY) => {
                        Json(serde_json::json!({ "projectId": "project-a" })).into_response()
                    }
                    Some(NO_WAAS_KEY) => StatusCode::FORBIDDEN.into_response(),
                    Some(FAILING_KEY) => StatusCode::BAD_GATEWAY.into_response(),
                    _ => StatusCode::UNAUTHORIZED.into_response(),
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener binds");
    let address = listener.local_addr().expect("listener has an address");
    tokio::spawn(async move { axum::serve(listener, app).await });
    (format!("http://{address}/v0"), lookups)
}

#[tokio::test]
async fn a_known_key_resolves_to_its_project_once_per_ttl() {
    let (url, lookups) = dev_api().await;
    let keys = ApiKeys::for_tests(&url);
    for _ in 0..3 {
        assert_eq!(
            keys.project(KEY).await,
            Ok(ProjectId::for_tests("project-a"))
        );
    }
    assert_eq!(lookups.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_unknown_key_is_refused_and_the_refusal_is_cached() {
    let (url, lookups) = dev_api().await;
    let keys = ApiKeys::for_tests(&url);
    let unknown = "11111111-2222-4333-8444-555555555555";
    for _ in 0..2 {
        assert_eq!(keys.project(unknown).await, Err(ApiError::ApiKeyInvalid));
    }
    assert_eq!(lookups.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_project_without_waas_is_refused_as_such() {
    let (url, lookups) = dev_api().await;
    let keys = ApiKeys::for_tests(&url);
    for _ in 0..2 {
        assert_eq!(
            keys.project(NO_WAAS_KEY).await,
            Err(ApiError::WaasNotEnabled)
        );
    }
    assert_eq!(lookups.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_malformed_key_is_refused_without_a_lookup() {
    let (url, lookups) = dev_api().await;
    let keys = ApiKeys::for_tests(&url);
    for malformed in ["", "a b", "key%20", &"a".repeat(65)] {
        assert_eq!(keys.project(malformed).await, Err(ApiError::ApiKeyInvalid));
    }
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_failed_lookup_is_a_424_and_is_not_cached() {
    let (url, lookups) = dev_api().await;
    let keys = ApiKeys::for_tests(&url);
    for _ in 0..2 {
        assert_eq!(
            keys.project(FAILING_KEY).await,
            Err(ApiError::ApiKeyLookupUnavailable)
        );
    }
    assert_eq!(lookups.load(Ordering::SeqCst), 2);
    let unreachable = ApiKeys::for_tests("http://127.0.0.1:9");
    assert_eq!(
        unreachable.project(KEY).await,
        Err(ApiError::ApiKeyLookupUnavailable)
    );
}

impl ApiKeys {
    pub(crate) fn for_tests(base_url: &str) -> Self {
        Self::new(&DevApiConfig {
            base_url: base_url.to_owned(),
            project_cache_secs: 300,
        })
        .expect("test api keys did not build")
    }
}
