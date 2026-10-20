//! Upstream client: UDP with TCP fallback on truncation, TCP, and `DoT` with connection reuse.
//!
//! Anti-spoofing: every attempt uses a fresh random query ID and (for UDP) a fresh socket bound to
//! an OS-randomised ephemeral port and connected to the upstream, so the kernel drops datagrams
//! from any other source. A response is accepted only if its ID, QR bit, opcode and question match
//! the query; mismatching UDP datagrams are ignored until the attempt times out.

mod spec;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
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

/// Sends queries to upstream resolvers.
pub struct UpstreamClient {
    config: UpstreamConfig,
    tls: TlsConnector,
    pool: Mutex<HashMap<Upstream, PooledConn>>,
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
        let addr = resolve(upstream).await?;
        let fut = async {
            match kind {
                Attempt::Udp => udp_exchange(addr, &wire, query).await,
                Attempt::Tcp => {
                    let mut stream = TcpStream::connect(addr).await?;
                    framed_exchange(&mut stream, &wire, query).await
                }
            }
        };
        timeout(self.config.timeout, fut)
            .await
            .map_err(|_| UpstreamError::Timeout)?
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
        let addr = resolve(upstream).await?;
        let name = ServerName::try_from(upstream.server_name().to_owned())
            .map_err(|e| UpstreamError::Tls(e.to_string()))?;
        let fut = async {
            let tcp = TcpStream::connect(addr).await?;
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

async fn resolve(upstream: &Upstream) -> Result<SocketAddr, UpstreamError> {
    lookup_host((upstream.host.as_str(), upstream.port))
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address for upstream").into())
}

/// A response matches when it answers this exact query.
fn matches(query: &Message, resp: &Message) -> bool {
    resp.header.qr
        && resp.header.id == query.header.id
        && resp.header.opcode == Opcode::Query
        && resp.questions == query.questions
}

async fn udp_exchange(
    addr: SocketAddr,
    wire: &[u8],
    query: &Message,
) -> Result<Message, UpstreamError> {
    let bind: SocketAddr = if addr.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    // Port 0: the OS picks a random ephemeral source port per query.
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(addr).await?;
    socket.send(wire).await?;
    let mut buf = vec![0u8; usize::from(u16::MAX)];
    loop {
        let n = socket.recv(&mut buf).await?;
        match Message::decode(&buf[..n]) {
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
