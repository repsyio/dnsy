//! REST API (axum + utoipa) and the embedded web UI.
//!
//! [`router`] builds the full service. [`openapi`] returns the `OpenAPI` document that is
//! checked in as `openapi/dnsy.json` (regenerate with `just openapi`).

pub mod auth;
pub mod error;
mod routes;
mod security;
pub mod state;
mod ui;

use axum::Json;
use axum::Router;
use axum::middleware;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_axum::router::OpenApiRouter;

pub use state::ApiState;

/// Options of the HTTP service.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApiConfig {
    /// The API is served over TLS: send `Strict-Transport-Security`.
    pub tls: bool,
}

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("dnsy_...")
                    .build(),
            ),
        );
        components.add_security_scheme(
            "session",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new(auth::SESSION_COOKIE))),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "DNSY REST API",
        description = "Management API of the DNSY DNS server. Errors are RFC 9457 problem+json.",
        license(name = "Apache-2.0"),
    ),
    modifiers(&SecurityAddon),
)]
struct ApiDoc;

fn assemble() -> (Router<ApiState>, utoipa::openapi::OpenApi) {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(routes::root())
        .nest("/api/v1", routes::v1())
        .split_for_parts()
}

/// The `OpenAPI` document, generated from the handler annotations.
#[must_use]
pub fn openapi() -> utoipa::openapi::OpenApi {
    assemble().1
}

/// The complete HTTP service: probes, `/api/v1`, `/api/openapi.json` and the UI.
pub fn router(state: ApiState, config: ApiConfig) -> Router {
    build(state, config, Router::new())
}

/// [`router`] plus `extra` routes that share the middleware (tests add probe routes).
fn build(state: ApiState, config: ApiConfig, extra: Router<ApiState>) -> Router {
    let (router, spec) = assemble();
    let mut state = state;
    state.cookie_secure = config.tls;
    router
        .merge(extra)
        .route(
            "/api/openapi.json",
            axum::routing::get(move || {
                let spec = spec.clone();
                async move { Json(spec) }
            }),
        )
        .fallback(ui::fallback)
        .layer(middleware::from_fn_with_state(
            config.tls,
            security::security_headers,
        ))
        .layer(middleware::from_fn(security::trace))
        .with_state(state)
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_auth;
