//! Embedded web UI with SPA fallback.
//!
//! The Angular build output (`web/dist/dnsy/browser`) is embedded with `rust-embed` when the
//! `embed-ui` feature is on. Without it the UI paths answer 404.

use std::borrow::Cow;

use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
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
pub async fn fallback(method: Method, uri: Uri) -> Response {
    if uri.path().starts_with("/api/") || !matches!(method, Method::GET | Method::HEAD) {
        return ApiError::NotFound("no such resource".to_owned()).into_response();
    }
    serve(uri.path(), embedded)
}

/// Resolve `uri_path` against `lookup`: exact file, else `index.html` for extension-less
/// (client-side route) paths, else 404.
pub fn serve(uri_path: &str, lookup: impl Fn(&str) -> Option<Asset>) -> Response {
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
    let (asset, is_index) = match lookup(if path.is_empty() { "index.html" } else { path }) {
        Some(a) => (a, path.is_empty() || path == "index.html"),
        None if !looks_like_file => match lookup("index.html") {
            Some(a) => (a, true),
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
    let mut res = (StatusCode::OK, asset.body.into_owned()).into_response();
    res.headers_mut().insert(header::CONTENT_TYPE, mime);
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(path: &str) -> Option<Asset> {
        let (body, mime) = match path {
            "index.html" => ("<html>spa</html>", "text/html"),
            "main-abc.js" => ("js", "text/javascript"),
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
            let r = serve(p, lookup);
            assert_eq!(r.status(), StatusCode::OK, "{p}");
            assert_eq!(r.headers()[header::CONTENT_TYPE], "text/html");
            assert_eq!(r.headers()[header::CACHE_CONTROL], "no-cache");
        }
    }

    #[test]
    fn assets_are_immutable_and_missing_files_404() {
        let r = serve("/main-abc.js", lookup);
        assert_eq!(r.status(), StatusCode::OK);
        assert!(
            r.headers()[header::CACHE_CONTROL]
                .to_str()
                .unwrap()
                .contains("immutable")
        );
        assert_eq!(serve("/missing.js", lookup).status(), StatusCode::NOT_FOUND);
        assert_eq!(serve("/a/../x", lookup).status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn no_index_is_404() {
        assert_eq!(serve("/", |_| None).status(), StatusCode::NOT_FOUND);
    }
}
