//! dnsy-server: plain DNS listeners (UDP and TCP).
//!
//! Listeners only frame bytes: they decode a query, hand it to a [`dnsy_engine::Handler`] with a
//! [`dnsy_engine::RequestContext`], and encode the response within the transport's size limit.
//!
//! Hardening: TCP connections are capped (excess connections are closed at once), every TCP read
//! of a frame is bound by the idle timeout (slowloris), in-flight work is bounded per socket and
//! per connection, malformed packets get a minimal FORMERR or are dropped, and UDP answers are
//! truncated to the client's EDNS payload size (at most 1232, or 512 without EDNS).

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

pub use query::{MAX_UDP_PAYLOAD, MIN_UDP_PAYLOAD};

/// Listener settings.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub udp: Vec<SocketAddr>,
    pub tcp: Vec<SocketAddr>,
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
}

impl Server {
    /// Binds every configured address and starts serving.
    ///
    /// # Errors
    /// Returns the bind error of the first address that cannot be bound.
    pub async fn start<H: Handler>(config: ServerConfig, handler: Arc<H>) -> io::Result<Server> {
        let (shutdown, rx) = watch::channel(false);
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
                tcp::Limits {
                    idle: config.tcp_idle,
                    max_conns: config.max_tcp_conns,
                    drain: config.drain,
                },
            )));
        }
        Ok(Server {
            shutdown,
            tasks,
            udp_addrs,
            tcp_addrs,
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

    /// Stops accepting work and waits for in-flight requests, at most the configured drain time.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
    }
}
