//! Gateway project UUID and API key extraction tests (INV-23).

use axum::http::Request;

use super::*;

#[test]
fn project_id_accepts_uuid_and_rejects_junk() {
    assert!(ProjectId::parse("0b4a3a9e-5f7e-4b4f-9c1e-0d9f2a1b3c4d").is_some());
    assert!(ProjectId::parse("").is_none());
    assert!(ProjectId::parse("a b").is_none());
    assert!(ProjectId::parse(&"a".repeat(65)).is_none());
}

fn parts(uri: &str, header: Option<&str>) -> Parts {
    let mut request = Request::builder().uri(uri);
    if let Some(value) = header {
        request = request.header(API_KEY_HEADER, value);
    }
    request
        .body(())
        .expect("test request builds")
        .into_parts()
        .0
}

#[test]
fn the_api_key_is_the_header_or_the_api_key_query_parameter() {
    let session = "/v1/private-wallet/session";
    assert_eq!(
        api_key(&parts(&format!("{session}?api-key=k1"), None)),
        Some("k1")
    );
    assert_eq!(
        api_key(&parts(&format!("{session}?a=1&api-key=k1"), None)),
        Some("k1")
    );
    assert_eq!(
        api_key(&parts(&format!("{session}?api-key=k1"), Some("k2"))),
        Some("k2")
    );
    assert_eq!(
        api_key(&parts(&format!("{session}?xapi-key=k1"), None)),
        None
    );
    assert_eq!(api_key(&parts(session, None)), None);
}

impl ProjectId {
    pub fn for_tests(value: &str) -> Self {
        Self(Arc::from(value))
    }
}
