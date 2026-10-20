//! `DoT` listener (RFC 7858): rustls in front of the TCP framing and limits.
//!
//! TLS 1.2 and 1.3 with rustls' default cipher suites (ring provider), ALPN `dot`. The handshake
//! runs inside the connection task and is bound by the idle timeout. Certificates are served
//! through [`certs::CertStore`] and hot-reloaded. Client certificate verification (mTLS) plugs in
//! through [`DotConfig::client_verifier`]; this module only forwards it to rustls.

pub(crate) mod certs;

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use dnsy_core::Transport;
use dnsy_engine::Handler;
use rustls::crypto::ring::default_provider;
use rustls::server::danger::ClientCertVerifier;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use crate::tcp::{self, Flavor, Limits};

/// ALPN protocol id for DNS over TLS (RFC 7858 section 3.1 / IANA).
pub(crate) const ALPN_DOT: &[u8] = b"dot";

/// `DoT` listener settings.
#[derive(Clone)]
pub struct DotConfig {
    pub listen: Vec<SocketAddr>,
    /// Certificate chain (PEM).
    pub cert: PathBuf,
    /// Private key (PEM).
    pub key: PathBuf,
    /// Client certificate verifier; `None` means no client authentication. The mTLS story
    /// supplies a `WebPkiClientVerifier` here.
    pub client_verifier: Option<Arc<dyn ClientCertVerifier>>,
}

impl std::fmt::Debug for DotConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DotConfig")
            .field("listen", &self.listen)
            .field("cert", &self.cert)
            .field("key", &self.key)
            .field("client_verifier", &self.client_verifier.is_some())
            .finish()
    }
}

impl DotConfig {
    #[must_use]
    pub fn new(listen: Vec<SocketAddr>, cert: PathBuf, key: PathBuf) -> Self {
        Self {
            listen,
            cert,
            key,
            client_verifier: None,
        }
    }
}

/// Builds the TLS acceptor around the reloadable certificate store.
pub(crate) fn acceptor(
    store: Arc<certs::CertStore>,
    verifier: Option<Arc<dyn ClientCertVerifier>>,
    alpn: &[&[u8]],
) -> io::Result<TlsAcceptor> {
    let builder = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?;
    let builder = match verifier {
        Some(v) => builder.with_client_cert_verifier(v),
        None => builder.with_no_client_auth(),
    };
    let mut config = builder.with_cert_resolver(store);
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub(crate) async fn serve<H: Handler>(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    handler: Arc<H>,
    shutdown: watch::Receiver<bool>,
    limits: Limits,
) {
    let idle = limits.idle;
    let wrap = move |stream| {
        let acceptor = acceptor.clone();
        async move {
            match tokio::time::timeout(idle, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => Some(tls),
                Ok(Err(e)) => {
                    tracing::debug!(error = %e, "dot handshake failed");
                    None
                }
                Err(_) => {
                    tracing::debug!("dot handshake timed out");
                    None
                }
            }
        }
    };
    let flavor = Flavor {
        transport: Transport::Dot,
        pad: true,
    };
    tcp::serve_with(listener, handler, shutdown, limits, flavor, wrap).await;
}
