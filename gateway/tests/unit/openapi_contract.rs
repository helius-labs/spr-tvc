//! Gateway committed OpenAPI contract verification test (INV-24).

use super::*;

#[test]
fn the_committed_openapi_document_is_current() {
    let current = ApiDoc::openapi()
        .to_pretty_json()
        .expect("the document serializes")
        + "\n";
    if std::env::var_os("BLESS_OPENAPI").is_some() {
        std::fs::write("openapi.json", &current).expect("openapi.json is writable");
    }
    let committed = std::fs::read_to_string("openapi.json").unwrap_or_default();
    assert!(
        committed == current,
        "openapi.json is stale; run `BLESS_OPENAPI=1 cargo test` in gateway"
    );
}
