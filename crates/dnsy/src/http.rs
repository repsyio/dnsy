//! Serves the API router over plain HTTP or TLS with graceful shutdown.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt as _;

use crate::{Error, Result};

/// How long open API connections (for example a live-tail stream) get after shutdown starts.
const DRAIN: Duration = Duration::from_secs(2);

/// TLS acceptor for the API from PEM files (read once at start).
pub(crate) fn acceptor(cert: &Path, key: &Path) -> Result<TlsAcceptor> {
    let chain = CertificateDer::pem_file_iter(cert)
        .map_err(|e| Error::msg(format!("api.tls_cert {}: {e}", cert.display())))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::msg(format!("api.tls_cert {}: {e}", cert.display())))?;
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| Error::msg(format!("api.tls_key {}: {e}", key.display())))?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(chain, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Accepts connections until `shutdown` flips, then lets open ones finish for [`DRAIN`].
pub(crate) async fn serve(
    listener: TcpListener,
    app: Router,
    tls: Option<TlsAcceptor>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut conns = JoinSet::new();
    loop {
        while conns.try_join_next().is_some() {}
        let (stream, peer) = tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok(a) => a,
                Err(e) => {
                    tracing::debug!(error = %e, "api accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let app = app.clone();
        let tls = tls.clone();
        let mut stop = shutdown.clone();
        conns.spawn(async move {
            let io: Box<dyn Io> = match tls {
                Some(acceptor) => match acceptor.accept(stream).await {
                    Ok(tls) => Box::new(tls),
                    Err(e) => {
                        tracing::debug!(%peer, error = %e, "api tls handshake failed");
                        return;
                    }
                },
                None => Box::new(stream),
            };
            let service = service_fn(move |req: hyper::Request<Incoming>| {
                app.clone().oneshot(req.map(axum::body::Body::new))
            });
            let builder = Builder::new(TokioExecutor::new());
            let conn = builder.serve_connection(TokioIo::new(io), service);
            tokio::pin!(conn);
            let result = tokio::select! {
                r = conn.as_mut() => r,
                _ = stop.changed() => {
                    conn.as_mut().graceful_shutdown();
                    conn.await
                }
            };
            if let Err(e) = result {
                tracing::debug!(%peer, error = %e, "api connection ended");
            }
        });
    }
    let _ = tokio::time::timeout(DRAIN, async { while conns.join_next().await.is_some() {} }).await;
}

trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}
