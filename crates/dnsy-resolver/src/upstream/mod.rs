//! Upstream client: UDP with TCP fallback on truncation, TCP, and `DoT` with connection reuse.
//!
//! Anti-spoofing: every attempt uses a fresh CSPRNG query ID. UDP goes over a small per-upstream
//! pool of sockets, each bound to an OS-randomised ephemeral port and connected to the upstream
//! (so the kernel drops datagrams from any other source), used by one query at a time and
//! replaced after [`UDP_ROTATE_QUERIES`] queries or [`UDP_ROTATE_AGE`], whichever comes first. A
//! socket whose attempt failed or timed out is closed, never pooled. A response is accepted only
//! if its ID, QR bit, opcode and full question section match the query; mismatching UDP
//! datagrams (including late answers to an earlier query on the same socket) are ignored until
//! the attempt times out.

mod spec;

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dnsy_proto::{DecodeError, EncodeError, Message, Opcode};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

pub use spec::{Upstream, UpstreamTransport};

/// EDNS UDP payload size advertised to upstreams.
pub const ADVERTISED_UDP_PAYLOAD: u16 = 1232;
/// Largest UDP response accepted (the receive buffer of a pooled socket). Above the advertised
/// size, so an upstream overshooting it a little is still understood.
pub const MAX_UDP_RESPONSE: usize = 4096;
/// A pooled UDP socket is closed after this many queries ...
pub const UDP_ROTATE_QUERIES: u32 = 128;
/// ... or this long after it was opened, whichever comes first. A host-name upstream is resolved
/// again at most this often.
pub const UDP_ROTATE_AGE: Duration = Duration::from_secs(60);
/// Idle UDP sockets kept per upstream; a query finding none opens a new one.
pub const UDP_POOL_IDLE: usize = 64;

/// Why an upstream query failed.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("invalid upstream address {0:?}")]
    InvalidUpstream(String),
    #[error("upstream timed out")]
    Timeout,
    #[error("upstream i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("upstream response does not match the query")]
    Mismatch,
    #[error("malformed upstream response: {0}")]
    Decode(#[from] DecodeError),
    #[error("cannot encode query: {0}")]
    Encode(#[from] EncodeError),
    #[error("query has no question")]
    NoQuestion,
}

/// Trust anchors used to verify `DoT` server certificates.
#[derive(Debug, Clone)]
pub enum TlsRoots {
    /// The bundled Mozilla root set.
    WebPki,
    /// Only these DER-encoded CA certificates.
    Custom(Vec<CertificateDer<'static>>),
}

/// Client tuning.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Budget for one attempt (connect, write and read). A TC retry gets its own attempt.
    pub timeout: Duration,
    /// A pooled `DoT` connection unused for this long is closed instead of reused.
    pub dot_idle: Duration,
    pub tls_roots: TlsRoots,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            dot_idle: Duration::from_secs(30),
            tls_roots: TlsRoots::WebPki,
        }
    }
}

struct PooledConn {
    stream: TlsStream<TcpStream>,
    last_used: Instant,
}

/// When pooled UDP sockets are replaced.
#[derive(Debug, Clone, Copy)]
struct Rotation {
    queries: u32,
    age: Duration,
}

/// A connected UDP socket with its receive buffer, used by one query at a time.
struct UdpConn {
    socket: UdpSocket,
    peer: SocketAddr,
    buf: Box<[u8]>,
    opened: Instant,
    uses: u32,
}

impl UdpConn {
    async fn open(peer: SocketAddr) -> io::Result<UdpConn> {
        let bind: SocketAddr = if peer.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            ([0u16; 8], 0).into()
        };
        // Port 0: the OS picks a random ephemeral source port for every new socket.
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(peer).await?;
        Ok(UdpConn {
            socket,
            peer,
            buf: vec![0u8; MAX_UDP_RESPONSE].into_boxed_slice(),
            opened: Instant::now(),
            uses: 0,
        })
    }

    fn reusable(&self, peer: SocketAddr, rotation: Rotation, now: Instant) -> bool {
        self.peer == peer
            && self.uses < rotation.queries
            && now.saturating_duration_since(self.opened) < rotation.age
    }
}

/// Where an upstream lives; `until` is `None` for an IP literal (never re-resolved).
#[derive(Clone, Copy)]
struct Resolved {
    addr: SocketAddr,
    until: Option<Instant>,
}

#[derive(Default)]
struct UdpState {
    resolved: Option<Resolved>,
    idle: Vec<UdpConn>,
}

/// Sends queries to upstream resolvers.
pub struct UpstreamClient {
    config: UpstreamConfig,
    tls: TlsConnector,
    pool: Mutex<HashMap<Upstream, PooledConn>>,
    udp: Mutex<HashMap<Upstream, UdpState>>,
    rotation: Rotation,
}

impl UpstreamClient {
    /// # Errors
    ///
    /// Fails when a custom CA certificate is unusable or TLS cannot be configured.
    pub fn new(config: UpstreamConfig) -> Result<Self, UpstreamError> {
        let mut roots = rustls::RootCertStore::empty();
        match &config.tls_roots {
            TlsRoots::WebPki => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            TlsRoots::Custom(certs) => {
                for cert in certs {
                    roots
                        .add(cert.clone())
                        .map_err(|e| UpstreamError::Tls(e.to_string()))?;
                }
            }
        }
        let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| UpstreamError::Tls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Self {
            config,
            tls: TlsConnector::from(Arc::new(tls_config)),
            pool: Mutex::new(HashMap::new()),
            udp: Mutex::new(HashMap::new()),
            rotation: Rotation {
                queries: UDP_ROTATE_QUERIES,
                age: UDP_ROTATE_AGE,
            },
        })
    }

    /// Sends `query` and returns the validated response.
    ///
    /// The query ID is replaced with a random one. EDNS is always attached (payload 1232); the
    /// caller's DO bit, CD bit and EDNS options are preserved. A truncated UDP answer is retried
    /// over TCP.
    ///
    /// # Errors
    ///
    /// Timeout, I/O, TLS, decode failures, or a response that does not match the query.
    pub async fn query(
        &self,
        upstream: &Upstream,
        query: &Message,
    ) -> Result<Message, UpstreamError> {
        if query.questions.is_empty() {
            return Err(UpstreamError::NoQuestion);
        }
        let mut query = query.clone();
        query.header.qr = false;
        query.edns.get_or_insert_default().udp_payload = ADVERTISED_UDP_PAYLOAD;

        match upstream.transport {
            UpstreamTransport::Udp => {
                let resp = self.attempt(upstream, &mut query, Attempt::Udp).await?;
                if resp.header.tc {
                    return self.attempt(upstream, &mut query, Attempt::Tcp).await;
                }
                Ok(resp)
            }
            UpstreamTransport::Tcp => self.attempt(upstream, &mut query, Attempt::Tcp).await,
            UpstreamTransport::Tls => self.query_dot(upstream, &mut query).await,
        }
    }

    async fn attempt(
        &self,
        upstream: &Upstream,
        query: &mut Message,
        kind: Attempt,
    ) -> Result<Message, UpstreamError> {
        query.header.id = random_id();
        let wire = query.encode(usize::from(u16::MAX))?;
        let udp = matches!(kind, Attempt::Udp);
        let (addr, pooled) = self.checkout(upstream, udp).await?;
        let query = &*query;
        let fut = async {
            match kind {
                Attempt::Udp => {
                    let mut conn = match pooled {
                        Some(conn) => conn,
                        None => UdpConn::open(addr).await?,
                    };
                    let resp = udp_exchange(&mut conn, &wire, query).await?;
                    Ok::<_, UpstreamError>((resp, Some(conn)))
                }
                Attempt::Tcp => {
                    let mut stream = TcpStream::connect(addr).await?;
                    stream.set_nodelay(true)?;
                    Ok((framed_exchange(&mut stream, &wire, query).await?, None))
                }
            }
        };
        // A timed-out or failed attempt drops its socket here: it is never pooled again.
        let (resp, conn) = timeout(self.config.timeout, fut)
            .await
            .map_err(|_| UpstreamError::Timeout)??;
        if let Some(conn) = conn {
            self.put_udp(upstream, conn);
        }
        Ok(resp)
    }

    /// The upstream's socket address: cached forever for an IP literal, for [`UDP_ROTATE_AGE`]
    /// for a host name.
    async fn resolve(&self, upstream: &Upstream) -> Result<SocketAddr, UpstreamError> {
        Ok(self.checkout(upstream, false).await?.0)
    }

    /// The upstream's address and, with `udp`, an idle pooled socket connected to it (sockets
    /// due for rotation are closed on the way), under one lock in the common case.
    async fn checkout(
        &self,
        upstream: &Upstream,
        udp: bool,
    ) -> Result<(SocketAddr, Option<UdpConn>), UpstreamError> {
        let now = Instant::now();
        if let Some(state) = self.udp_state().get_mut(upstream)
            && let Some(r) = state
                .resolved
                .filter(|r| r.until.is_none_or(|until| now < until))
        {
            let conn = if udp {
                let rotation = self.rotation;
                state.idle.retain(|c| c.reusable(r.addr, rotation, now));
                state.idle.pop()
            } else {
                None
            };
            return Ok((r.addr, conn));
        }
        let resolved = if let Ok(ip) = upstream.host.parse::<IpAddr>() {
            Resolved {
                addr: SocketAddr::new(ip, upstream.port),
                until: None,
            }
        } else {
            let addr = lookup_host((upstream.host.as_str(), upstream.port))
                .await?
                .next()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "no address for upstream")
                })?;
            Resolved {
                addr,
                until: Some(now + self.rotation.age),
            }
        };
        self.udp_state()
            .entry(upstream.clone())
            .or_default()
            .resolved = Some(resolved);
        Ok((resolved.addr, None))
    }

    fn udp_state(&self) -> std::sync::MutexGuard<'_, HashMap<Upstream, UdpState>> {
        self.udp
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Returns a socket after a successful exchange, unless it is due for rotation or the pool
    /// is full (then it is closed).
    fn put_udp(&self, upstream: &Upstream, mut conn: UdpConn) {
        conn.uses += 1;
        if !conn.reusable(conn.peer, self.rotation, Instant::now()) {
            return;
        }
        let mut state = self.udp_state();
        let idle = &mut state.entry(upstream.clone()).or_default().idle;
        if idle.len() < UDP_POOL_IDLE {
            idle.push(conn);
        }
    }

    async fn query_dot(
        &self,
        upstream: &Upstream,
        query: &mut Message,
    ) -> Result<Message, UpstreamError> {
        let reused = self.take_pooled(upstream);
        if let Some(conn) = reused {
            query.header.id = random_id();
            let wire = query.encode(usize::from(u16::MAX))?;
            let mut stream = conn.stream;
            let result = timeout(
                self.config.timeout,
                framed_exchange(&mut stream, &wire, query),
            )
            .await;
            match result {
                Ok(Ok(resp)) => {
                    self.put_pooled(upstream, stream);
                    return Ok(resp);
                }
                // A stale connection (closed by the peer) is retried once on a fresh one.
                Ok(Err(UpstreamError::Io(_))) | Err(_) => {}
                Ok(Err(e)) => return Err(e),
            }
        }
        query.header.id = random_id();
        let wire = query.encode(usize::from(u16::MAX))?;
        let addr = self.resolve(upstream).await?;
        let name = ServerName::try_from(upstream.server_name().to_owned())
            .map_err(|e| UpstreamError::Tls(e.to_string()))?;
        let fut = async {
            let tcp = TcpStream::connect(addr).await?;
            tcp.set_nodelay(true)?;
            let mut stream = self
                .tls
                .connect(name, tcp)
                .await
                .map_err(|e| UpstreamError::Tls(e.to_string()))?;
            let resp = framed_exchange(&mut stream, &wire, query).await?;
            Ok::<_, UpstreamError>((resp, stream))
        };
        let (resp, stream) = timeout(self.config.timeout, fut)
            .await
            .map_err(|_| UpstreamError::Timeout)??;
        self.put_pooled(upstream, stream);
        Ok(resp)
    }

    fn take_pooled(&self, upstream: &Upstream) -> Option<PooledConn> {
        let idle = self.config.dot_idle;
        let mut pool = self
            .pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Dropping an expired entry closes its socket.
        pool.retain(|_, c| c.last_used.elapsed() < idle);
        pool.remove(upstream)
    }

    fn put_pooled(&self, upstream: &Upstream, stream: TlsStream<TcpStream>) {
        let mut pool = self
            .pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pool.insert(
            upstream.clone(),
            PooledConn {
                stream,
                last_used: Instant::now(),
            },
        );
    }
}

#[derive(Clone, Copy)]
enum Attempt {
    Udp,
    Tcp,
}

fn random_id() -> u16 {
    let mut b = [0u8; 2];
    rand::fill(&mut b[..]);
    u16::from_be_bytes(b)
}

/// A response matches when it answers this exact query.
fn matches(query: &Message, resp: &Message) -> bool {
    resp.header.qr
        && resp.header.id == query.header.id
        && resp.header.opcode == Opcode::Query
        && resp.questions == query.questions
}

async fn udp_exchange(
    conn: &mut UdpConn,
    wire: &[u8],
    query: &Message,
) -> Result<Message, UpstreamError> {
    conn.socket.send(wire).await?;
    loop {
        let n = conn.socket.recv(&mut conn.buf).await?;
        match Message::decode(&conn.buf[..n]) {
            Ok(resp) if matches(query, &resp) => return Ok(resp),
            // Spoofed, stale or garbled datagram: keep waiting until the attempt times out.
            _ => {}
        }
    }
}

async fn framed_exchange<S>(
    stream: &mut S,
    wire: &[u8],
    query: &Message,
) -> Result<Message, UpstreamError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let len = u16::try_from(wire.len()).map_err(|_| EncodeError::DoesNotFit)?;
    let mut out = Vec::with_capacity(wire.len() + 2);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(wire);
    stream.write_all(&out).await?;
    stream.flush().await?;
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
    stream.read_exact(&mut body).await?;
    let resp = Message::decode(&body)?;
    if matches(query, &resp) {
        Ok(resp)
    } else {
        Err(UpstreamError::Mismatch)
    }
}

#[cfg(test)]
mod tests;
