//! Serves the API router over plain HTTP or TLS with graceful shutdown.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
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
            // Handlers read the peer address from `ConnectInfo` (login throttling is keyed on it).
            let service = service_fn(move |req: hyper::Request<Incoming>| {
                let mut req = req.map(axum::body::Body::new);
                req.extensions_mut().insert(ConnectInfo(peer));
                app.clone().oneshot(req)
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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use dnsy_api::{ApiConfig, ApiState, router};
    use dnsy_core::Role;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use serde_json::json;

    use super::*;

    const PW: &str = "correct horse battery";

    struct Server {
        addr: SocketAddr,
        store: dnsy_store::Store,
        _stop: watch::Sender<bool>,
        _dir: tempfile::TempDir,
    }

    async fn server() -> Server {
        let dir = tempfile::tempdir().unwrap();
        let store = dnsy_store::Store::open(&dir.path().join("t.db")).unwrap();
        let state = ApiState::new(store.clone());
        state.users.create("admin", PW, Role::Admin).await.unwrap();
        let app = router(state.clone(), ApiConfig { tls: false });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = watch::channel(false);
        tokio::spawn(serve(listener, app, None, rx));
        Server {
            addr,
            store,
            _stop: stop,
            _dir: dir,
        }
    }

    /// Posts a login from the given loopback source address; returns status and headers text.
    async fn login(s: &Server, from: &str, password: &str) -> (u16, String) {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind(SocketAddr::new(from.parse().unwrap(), 0)).unwrap();
        let mut stream = socket.connect(s.addr).await.unwrap();
        let body = json!({"username": "admin", "password": password}).to_string();
        let request = format!(
            "POST /api/v1/auth/login HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\
             content-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).await.unwrap();
        let status = raw.split(' ').nth(1).unwrap().parse().unwrap();
        (status, raw.to_ascii_lowercase())
    }

    async fn recorded_ips(s: &Server) -> Vec<String> {
        s.store
            .read(|c| {
                let mut stmt = c.prepare("SELECT DISTINCT ip FROM login_attempts")?;
                Ok(stmt
                    .query_map([], |r| r.get(0))?
                    .collect::<std::result::Result<Vec<String>, _>>()?)
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn login_attempts_record_peer_ip_through_real_listener() {
        let s = server().await;
        assert_eq!(login(&s, "127.0.0.2", "wrong-password").await.0, 401);
        let ips = recorded_ips(&s).await;
        assert_eq!(ips, vec!["127.0.0.2".to_owned()]);
    }

    #[tokio::test]
    async fn locked_out_address_does_not_lock_out_another_address() {
        let s = server().await;
        for _ in 0..5 {
            assert_eq!(login(&s, "127.0.0.2", "wrong-password").await.0, 401);
        }
        let (status, raw) = login(&s, "127.0.0.2", PW).await;
        assert_eq!(status, 429);
        assert!(raw.contains("retry-after:"));
        // The attacker's address is locked; the administrator elsewhere is not.
        assert_eq!(login(&s, "127.0.0.3", PW).await.0, 200);
        assert!(!recorded_ips(&s).await.contains(&"0.0.0.0".to_owned()));
    }
}
