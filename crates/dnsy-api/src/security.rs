//! Response security headers and request tracing.

use std::time::Instant;

use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

const CSP: &str = "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'";
const HSTS: &str = "max-age=63072000; includeSubDomains";

/// Add the security headers to every response. `hsts` is set when the API is served over TLS.
pub async fn security_headers(State(hsts): State<bool>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let is_api = path.starts_with("/api/") || matches!(path, "/healthz" | "/readyz");
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    let fixed: [(HeaderName, &'static str); 6] = [
        (header::CONTENT_SECURITY_POLICY, CSP),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ),
        (
            HeaderName::from_static("permissions-policy"),
            "camera=(), microphone=(), geolocation=()",
        ),
    ];
    for (name, value) in fixed {
        h.insert(name, HeaderValue::from_static(value));
    }
    if hsts {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(HSTS),
        );
    }
    if is_api {
        h.entry(header::CACHE_CONTROL)
            .or_insert(HeaderValue::from_static("no-store"));
    }
    res
}

/// Log method, path, status and latency. Headers (`Authorization`, `Cookie`) and the query
/// string are never logged, so credentials cannot leak into traces.
pub async fn trace(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let start = Instant::now();
    let res = next.run(req).await;
    tracing::info!(
        %method,
        path,
        status = res.status().as_u16(),
        latency_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
        "api request"
    );
    res
}
