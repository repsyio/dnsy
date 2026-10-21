//! Embedded web UI with SPA fallback.
//!
//! The Angular build output (`web/dist/dnsy/browser`) is embedded with `rust-embed` when the
//! `embed-ui` feature is on. Without it the UI paths answer 404.

use std::borrow::Cow;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, Uri, header};
use axum::response::{IntoResponse, Response};

use crate::error::ApiError;

const ASSET_EXTENSIONS: &[&str] = &[
    "js",
    "mjs",
    "css",
    "map",
    "ico",
    "png",
    "jpg",
    "jpeg",
    "svg",
    "webp",
    "woff",
    "woff2",
    "ttf",
    "json",
    "txt",
    "webmanifest",
    "wasm",
];

/// One embedded file.
pub struct Asset {
    pub body: Cow<'static, [u8]>,
    pub mime: String,
}

#[cfg(feature = "embed-ui")]
#[derive(rust_embed::RustEmbed)]
#[folder = "../../web/dist/dnsy/browser"]
struct Embedded;

#[cfg(feature = "embed-ui")]
fn mime_for(path: &str) -> &'static str {
    match path.rsplit_once('.').map_or("", |(_, e)| e) {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "wasm" => "application/wasm",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(feature = "embed-ui")]
fn embedded(path: &str) -> Option<Asset> {
    let f = Embedded::get(path)?;
    Some(Asset {
        body: f.data,
        mime: mime_for(path).to_owned(),
    })
}

#[cfg(not(feature = "embed-ui"))]
fn embedded(_path: &str) -> Option<Asset> {
    None
}

/// Router fallback: API paths 404 as problem+json, everything else is the UI.
pub async fn fallback(method: Method, uri: Uri, headers: HeaderMap) -> Response {
    if uri.path().starts_with("/api/") || !matches!(method, Method::GET | Method::HEAD) {
        return ApiError::NotFound("no such resource".to_owned()).into_response();
    }
    let accept = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    serve(uri.path(), accept, embedded)
}

/// Content codings the build step precompresses (`<file>.br`, `<file>.gz`), best first.
const ENCODINGS: [(&str, &str); 2] = [("br", ".br"), ("gzip", ".gz")];

/// Whether an `Accept-Encoding` value allows `coding` (listed with a non-zero q-value).
fn accepts(header: &str, coding: &str) -> bool {
    header.split(',').any(|item| {
        let mut parts = item.split(';');
        parts
            .next()
            .is_some_and(|c| c.trim().eq_ignore_ascii_case(coding))
            && parts.all(|p| {
                p.trim()
                    .strip_prefix("q=")
                    .is_none_or(|q| q.trim().parse::<f32>().is_ok_and(|q| q > 0.0))
            })
    })
}

/// Resolve `uri_path` against `lookup`: exact file, else `index.html` for extension-less
/// (client-side route) paths, else 404.
pub fn serve(
    uri_path: &str,
    accept_encoding: &str,
    lookup: impl Fn(&str) -> Option<Asset>,
) -> Response {
    let path = uri_path.trim_start_matches('/');
    let not_found = || ApiError::NotFound("no such resource".to_owned()).into_response();
    if path.split('/').any(|s| s == "..") {
        return not_found();
    }
    // Route segments can contain dots (zone names), so only known asset extensions count.
    let looks_like_file = path
        .rsplit('/')
        .next()
        .and_then(|s| s.rsplit_once('.'))
        .is_some_and(|(_, ext)| ASSET_EXTENSIONS.contains(&ext));
    let requested = if path.is_empty() { "index.html" } else { path };
    let (name, asset, is_index) = match lookup(requested) {
        Some(a) => (requested, a, requested == "index.html"),
        None if !looks_like_file => match lookup("index.html") {
            Some(a) => ("index.html", a, true),
            None => return not_found(),
        },
        None => return not_found(),
    };
    let cache = if is_index {
        "no-cache"
    } else {
        "public, max-age=31536000, immutable"
    };
    let Ok(mime) = HeaderValue::from_str(&asset.mime) else {
        return not_found();
    };
    // Serve the precompressed sibling when the client accepts it; the body stays borrowed from
    // the embedded data (no copy).
    let encoded = ENCODINGS
        .iter()
        .filter(|(coding, _)| accepts(accept_encoding, coding))
        .find_map(|(coding, ext)| lookup(&format!("{name}{ext}")).map(|a| (*coding, a.body)));
    let has_variants = encoded.is_some()
        || ENCODINGS
            .iter()
            .any(|(_, ext)| lookup(&format!("{name}{ext}")).is_some());
    let (body, coding) = match encoded {
        Some((coding, body)) => (body, Some(coding)),
        None => (asset.body, None),
    };
    let mut res = Response::new(Body::from(body));
    if let Some(coding) = coding {
        res.headers_mut()
            .insert(header::CONTENT_ENCODING, HeaderValue::from_static(coding));
    }
    if has_variants {
        res.headers_mut()
            .insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }
    res.headers_mut().insert(header::CONTENT_TYPE, mime);
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    fn lookup(path: &str) -> Option<Asset> {
        let (body, mime) = match path {
            "index.html" => ("<html>spa</html>", "text/html"),
            "main-abc.js" => ("js", "text/javascript"),
            "main-abc.js.br" => ("br-bytes", "application/octet-stream"),
            "main-abc.js.gz" => ("gz-bytes", "application/octet-stream"),
            _ => return None,
        };
        Some(Asset {
            body: Cow::Borrowed(body.as_bytes()),
            mime: mime.to_owned(),
        })
    }

    #[test]
    fn root_and_unknown_route_serve_index() {
        for p in ["/", "/zones/example.com"] {
            let r = serve(p, "", lookup);
            assert_eq!(r.status(), StatusCode::OK, "{p}");
            assert_eq!(r.headers()[header::CONTENT_TYPE], "text/html");
            assert_eq!(r.headers()[header::CACHE_CONTROL], "no-cache");
        }
    }

    #[test]
    fn assets_are_immutable_and_missing_files_404() {
        let r = serve("/main-abc.js", "", lookup);
        assert_eq!(r.status(), StatusCode::OK);
        assert!(
            r.headers()[header::CACHE_CONTROL]
                .to_str()
                .unwrap()
                .contains("immutable")
        );
        assert_eq!(
            serve("/missing.js", "", lookup).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(serve("/a/../x", "", lookup).status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn no_index_is_404() {
        assert_eq!(serve("/", "", |_| None).status(), StatusCode::NOT_FOUND);
    }

    async fn body(r: Response) -> Vec<u8> {
        axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn precompressed_sibling_is_served_when_accepted() {
        let r = serve("/main-abc.js", "gzip, br", lookup);
        assert_eq!(r.headers()[header::CONTENT_ENCODING], "br");
        assert_eq!(r.headers()[header::VARY], "Accept-Encoding");
        assert_eq!(r.headers()[header::CONTENT_TYPE], "text/javascript");
        assert_eq!(body(r).await, b"br-bytes");
        let r = serve("/main-abc.js", "gzip;q=0.8", lookup);
        assert_eq!(r.headers()[header::CONTENT_ENCODING], "gzip");
        assert_eq!(body(r).await, b"gz-bytes");
    }

    #[tokio::test]
    async fn identity_when_not_accepted_or_no_sibling() {
        for accept in ["", "identity", "br;q=0, gzip;q=0", "deflate"] {
            let r = serve("/main-abc.js", accept, lookup);
            assert!(
                r.headers().get(header::CONTENT_ENCODING).is_none(),
                "{accept}"
            );
            assert_eq!(r.headers()[header::VARY], "Accept-Encoding");
            assert_eq!(body(r).await, b"js");
        }
        let r = serve("/", "br", lookup);
        assert!(r.headers().get(header::CONTENT_ENCODING).is_none());
        assert!(r.headers().get(header::VARY).is_none());
    }
}
