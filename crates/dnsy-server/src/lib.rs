//! dnsy-server: plain DNS listeners (UDP, TCP and `DoT`).
//!
//! Listeners only frame bytes: they decode a query, hand it to a [`dnsy_engine::Handler`] with a
//! [`dnsy_engine::RequestContext`], and encode the response within the transport's size limit.
//!
//! `DoH` (RFC 8484) runs hyper (HTTP/1.1 and HTTP/2) behind the same rustls setup; see
//! [`DohConfig`].
//!
//! `DoT` reuses the TCP framing and limits behind rustls; see [`DotConfig`].
//!
//! Hardening: TCP connections are capped (excess connections are closed at once), every TCP read
//! of a frame is bound by the idle timeout (slowloris), in-flight work is bounded per socket and
//! per connection, malformed packets get a minimal FORMERR or are dropped, and UDP answers are
//! truncated to the client's EDNS payload size (at most 1232, or 512 without EDNS).

mod doh;
mod dot;
mod query;
mod tcp;
mod udp;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dnsy_engine::Handler;
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub use doh::{DohAuthenticator, DohConfig, DohDenied, TokenAuth};
pub use dot::DotConfig;
pub use dot::mtls::{AllowedCert, Allowlist, Clock as MtlsClock, MtlsMode, MtlsVerifier};
pub use query::{MAX_UDP_PAYLOAD, MIN_UDP_PAYLOAD};

/// Listener settings.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub udp: Vec<SocketAddr>,
    pub tcp: Vec<SocketAddr>,
    /// Optional `DoT` listener; it shares the TCP idle timeout, connection cap and drain time.
    pub dot: Option<DotConfig>,
    /// Optional `DoH` listener; it shares the TCP idle timeout, connection cap and drain time.
    pub doh: Option<DohConfig>,
    /// Close a TCP connection that sends no complete frame for this long.
    pub tcp_idle: Duration,
    /// Maximum concurrent TCP connections; further connections are closed immediately.
    pub max_tcp_conns: usize,
    /// How long shutdown waits for in-flight requests.
    pub drain: Duration,
}

impl ServerConfig {
    /// Defaults matching `[limits]`: 10 s idle, 1024 connections, 5 s drain.
    #[must_use]
    pub fn new(udp: Vec<SocketAddr>, tcp: Vec<SocketAddr>) -> Self {
        Self {
            udp,
            tcp,
            dot: None,
            doh: None,
            tcp_idle: Duration::from_millis(10_000),
            max_tcp_conns: 1024,
            drain: Duration::from_secs(5),
        }
    }
}

/// Running UDP and TCP listeners.
#[derive(Debug)]
pub struct Server {
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    udp_addrs: Vec<SocketAddr>,
    tcp_addrs: Vec<SocketAddr>,
    dot_addrs: Vec<SocketAddr>,
    doh_addrs: Vec<SocketAddr>,
}

impl Server {
    /// Binds every configured address and starts serving.
    ///
    /// # Errors
    /// Returns the bind error of the first address that cannot be bound.
    pub async fn start<H: Handler>(config: ServerConfig, handler: Arc<H>) -> io::Result<Server> {
        let (shutdown, rx) = watch::channel(false);
        let limits = tcp::Limits {
            idle: config.tcp_idle,
            max_conns: config.max_tcp_conns,
            drain: config.drain,
        };
        let mut tasks = Vec::new();
        let mut udp_addrs = Vec::new();
        let mut tcp_addrs = Vec::new();
        for addr in &config.udp {
            let socket = tokio::net::UdpSocket::bind(addr).await?;
            udp_addrs.push(socket.local_addr()?);
            tasks.push(tokio::spawn(udp::serve(
                socket,
                Arc::clone(&handler),
                rx.clone(),
                config.drain,
            )));
        }
        for addr in &config.tcp {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tcp_addrs.push(listener.local_addr()?);
            tasks.push(tokio::spawn(tcp::serve(
                listener,
                Arc::clone(&handler),
                rx.clone(),
                limits,
            )));
        }
        let mut dot_addrs = Vec::new();
        if let Some(dot) = &config.dot {
            let store = dot::certs::CertStore::load(&dot.cert, &dot.key)?;
            let acceptor = dot::acceptor(
                Arc::clone(&store),
                dot.client_verifier.clone(),
                &[dot::ALPN_DOT],
            )?;
            for addr in &dot.listen {
                let listener = tokio::net::TcpListener::bind(addr).await?;
                dot_addrs.push(listener.local_addr()?);
                tasks.push(tokio::spawn(dot::serve(
                    listener,
                    acceptor.clone(),
                    Arc::clone(&handler),
                    rx.clone(),
                    limits,
                    dot.mtls().cloned(),
                )));
            }
            tasks.push(dot::certs::watch_reloads(store, rx.clone())?);
        }
        let mut doh_bound = Vec::new();
        if let Some(doh) = config.doh {
            let store = dot::certs::CertStore::load(&doh.cert, &doh.key)?;
            let acceptor = dot::acceptor(Arc::clone(&store), None, doh::ALPN)?;
            let state = doh::State::new(&doh, Arc::clone(&handler), config.tcp_idle);
            for addr in &doh.listen {
                let listener = tokio::net::TcpListener::bind(addr).await?;
                doh_bound.push(listener.local_addr()?);
                tasks.push(tokio::spawn(doh::serve(
                    listener,
                    acceptor.clone(),
                    Arc::clone(&state),
                    rx.clone(),
                    limits,
                )));
            }
            tasks.push(dot::certs::watch_reloads(store, rx.clone())?);
        }
        Ok(Server {
            shutdown,
            tasks,
            udp_addrs,
            tcp_addrs,
            dot_addrs,
            doh_addrs: doh_bound,
        })
    }

    /// Bound UDP addresses (useful with port 0).
    #[must_use]
    pub fn udp_addrs(&self) -> &[SocketAddr] {
        &self.udp_addrs
    }

    /// Bound TCP addresses (useful with port 0).
    #[must_use]
    pub fn tcp_addrs(&self) -> &[SocketAddr] {
        &self.tcp_addrs
    }

    /// Bound `DoT` addresses (useful with port 0).
    #[must_use]
    pub fn dot_addrs(&self) -> &[SocketAddr] {
        &self.dot_addrs
    }

    /// Bound `DoH` addresses (useful with port 0).
    #[must_use]
    pub fn doh_addrs(&self) -> &[SocketAddr] {
        &self.doh_addrs
    }

    /// Stops accepting work and waits for in-flight requests, at most the configured drain time.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
    }
}
