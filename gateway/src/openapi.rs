//! The public API as the edge proxy serves it, as OpenAPI 3.1. `openapi.json` is
//! this document; `BLESS_OPENAPI=1 cargo test` rewrites it.

use strum::VariantNames;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::openapi::{RefOr, Schema};
use utoipa::{Modify, OpenApi};

use crate::error::{ApiError, Problem};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Helius Decryption Service API",
        version = "1",
        description = "The public edge front of the decryption enclave. An operation forwards \
                       the encrypted request and returns the Boot Proof of the replica that \
                       signed the reply. The client checks that proof and the App Proof \
                       against the signed pin.",
    ),
    servers(
        (url = "https://devnet.helius-rpc.com", description = "Devnet"),
        (url = "https://mainnet.helius-rpc.com", description = "Mainnet")
    ),
    paths(
        crate::app::decryption_operations,
    ),
    components(schemas(Problem)),
    modifiers(&HeliusApiKey, &ErrorCodes),
    security(("api-key" = [])),
)]
pub struct ApiDoc;

struct HeliusApiKey;

impl Modify for HeliusApiKey {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi
            .components
            .get_or_insert_with(Default::default)
            .add_security_scheme(
                "api-key",
                SecurityScheme::ApiKey(ApiKey::Query(ApiKeyValue::with_description(
                    "api-key",
                    "Your Helius API key.",
                ))),
            );
    }
}

/// Lists every error code in `Problem.code`.
struct ErrorCodes;

impl Modify for ErrorCodes {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let code = openapi
            .components
            .as_mut()
            .and_then(|components| components.schemas.get_mut("Problem"))
            .and_then(|problem| match problem {
                RefOr::T(Schema::Object(problem)) => problem.properties.get_mut("code"),
                _ => None,
            });
        if let Some(RefOr::T(Schema::Object(code))) = code {
            code.enum_values = Some(ApiError::VARIANTS.iter().map(|&v| v.into()).collect());
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/openapi_contract.rs"]
mod tests;
