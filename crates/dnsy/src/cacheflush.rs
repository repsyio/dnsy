//! `cache flush`: asks a running server's API to drop cache entries.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dnsy_config::Config;
use dnsy_proto::Name;

use crate::cli::CacheCommand;
use crate::{Error, Result};

pub(crate) async fn run(config: &Config, cmd: CacheCommand, out: &mut impl Write) -> Result<()> {
    let CacheCommand::Flush {
        name,
        subtree,
        url,
        token,
    } = cmd;
    let base = url.unwrap_or_else(|| default_base(config));
    let path = request_path(name.as_deref(), subtree)?;
    let client = client()?;
    let response = client
        .delete(format!("{}{path}", base.trim_end_matches('/')))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| Error::msg(format!("cannot reach the API at {base}: {e}")))?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|e| Error::msg(format!("reading the API response: {e}")))?;
    if !status.is_success() {
        return Err(Error::msg(format!(
            "the API answered {status}: {}",
            String::from_utf8_lossy(&body)
        )));
    }
    let removed = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v["removed"].as_u64())
        .unwrap_or(0);
    writeln!(out, "flushed {removed} cache entries")?;
    Ok(())
}

/// Where the API of this configuration listens, as seen from the same host.
pub(crate) fn default_base(config: &Config) -> String {
    let tls = config.api.tls_cert.is_some();
    if tls && let Some(public) = &config.api.public_url {
        return public.clone();
    }
    let addr = config
        .api
        .listen
        .first()
        .copied()
        .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::LOCALHOST, 5380)));
    let ip = if addr.ip().is_unspecified() {
        match addr.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        }
    } else {
        addr.ip()
    };
    let scheme = if tls { "https" } else { "http" };
    format!("{scheme}://{}", SocketAddr::new(ip, addr.port()))
}

/// `/api/v1/cache` or `/api/v1/cache/entries?name=..&subtree=..`.
pub(crate) fn request_path(name: Option<&str>, subtree: bool) -> Result<String> {
    let Some(name) = name else {
        return Ok("/api/v1/cache".to_owned());
    };
    let name = Name::from_ascii(name)
        .map_err(|e| Error::msg(format!("`{name}` is not a domain name: {e}")))?
        .to_lowercase()
        .to_string();
    let encoded: String = name
        .bytes()
        .map(|b| match b {
            b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' => char::from(b).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect();
    Ok(format!(
        "/api/v1/cache/entries?name={encoded}&subtree={subtree}"
    ))
}

fn client() -> Result<reqwest::Client> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_encode_names() {
        assert_eq!(request_path(None, false).unwrap(), "/api/v1/cache");
        assert_eq!(
            request_path(Some("Example.COM"), true).unwrap(),
            "/api/v1/cache/entries?name=example.com.&subtree=true"
        );
        assert!(request_path(Some(&"a".repeat(70)), false).is_err());
    }

    #[test]
    fn default_base_uses_loopback_for_wildcards() {
        let c = Config::from_toml("[api]\nlisten = [\"0.0.0.0:6000\"]").unwrap();
        assert_eq!(default_base(&c), "http://127.0.0.1:6000");
    }
}
