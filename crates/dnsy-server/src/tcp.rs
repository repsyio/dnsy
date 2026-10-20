//! TCP listener: RFC 1035 2-byte framing, RFC 7766 pipelining with out-of-order responses.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dnsy_core::Transport;
use dnsy_engine::{Handler, RequestContext};
use dnsy_proto::Edns;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::dot::mtls::ClientSession;
use crate::query::{Incoming, encode_response, pad_response, parse};

/// Concurrent requests per connection; the reader stops reading when reached (back-pressure).
const MAX_IN_FLIGHT_PER_CONN: usize = 32;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub idle: Duration,
    pub max_conns: usize,
    pub drain: Duration,
}

pub(crate) async fn serve<H: Handler>(
    listener: TcpListener,
    handler: Arc<H>,
    shutdown: watch::Receiver<bool>,
    limits: Limits,
) {
    let wrap = |stream: TcpStream| std::future::ready(Some((stream, None)));
    serve_with(listener, handler, shutdown, limits, Flavor::PLAIN, wrap).await;
}

/// What differs between plain TCP and `DoT` once the stream is established.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Flavor {
    pub transport: Transport,
    /// Pad responses (RFC 7830/8467) to clients that sent a Padding option.
    pub pad: bool,
}

impl Flavor {
    pub(crate) const PLAIN: Flavor = Flavor {
        transport: Transport::Tcp,
        pad: false,
    };
}

/// Accept loop shared by TCP and `DoT`. `wrap` turns an accepted socket into the byte stream the
/// framing runs on (the identity for TCP, the TLS handshake for `DoT`); `None` closes the socket.
/// It also returns the authenticated client session, if any (mTLS). It runs inside the connection
/// task, after the connection slot is taken.
pub(crate) async fn serve_with<H, S, F, Fut>(
    listener: TcpListener,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
    limits: Limits,
    flavor: Flavor,
    wrap: F,
) where
    H: Handler,
    S: AsyncRead + AsyncWrite + Send + 'static,
    F: Fn(TcpStream) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Option<(S, Option<ClientSession>)>> + Send,
{
    let slots = Arc::new(Semaphore::new(limits.max_conns));
    let mut conns = JoinSet::new();
    loop {
        while conns.try_join_next().is_some() {}
        let (stream, client) = tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok(a) => a,
                Err(e) => {
                    tracing::debug!(error = %e, "tcp accept failed");
                    // Avoid a hot loop on persistent errors such as fd exhaustion.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            tracing::debug!(%client, "tcp connection limit reached; closing");
            continue; // dropping the stream closes it
        };
        let handler = Arc::clone(&handler);
        let shutdown = shutdown.clone();
        let wrap = wrap.clone();
        conns.spawn(async move {
            if let Some((stream, session)) = wrap(stream).await {
                connection(stream, client, session, handler, shutdown, limits, flavor).await;
            }
            drop(permit);
        });
    }
    let _ = timeout(limits.drain, async {
        while conns.join_next().await.is_some() {}
    })
    .await;
}

async fn connection<H: Handler, S: AsyncRead + AsyncWrite + Send + 'static>(
    stream: S,
    client: SocketAddr,
    mut session: Option<ClientSession>,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
    limits: Limits,
    flavor: Flavor,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(MAX_IN_FLIGHT_PER_CONN);
    let idle = limits.idle;
    let writer_task = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            let Ok(len) = u16::try_from(bytes.len()) else {
                continue;
            };
            let write = async {
                writer.write_all(&len.to_be_bytes()).await?;
                writer.write_all(&bytes).await
            };
            if !matches!(timeout(idle, write).await, Ok(Ok(()))) {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    let mut requests = JoinSet::new();
    loop {
        while requests.try_join_next().is_some() {}
        if requests.len() >= MAX_IN_FLIGHT_PER_CONN {
            requests.join_next().await;
        }
        // The whole frame must arrive within the idle time, so slow drip-feeding is cut off too.
        let frame = tokio::select! {
            _ = shutdown.changed() => break,
            frame = timeout(idle, read_frame(&mut reader)) => frame,
        };
        // Anything but a frame: peer closed, I/O error, empty frame or idle timeout.
        let Ok(Ok(Some(packet))) = frame else { break };
        match parse(&packet) {
            // Garbage on a stream cannot be re-synchronised; answer if possible and close.
            Incoming::Drop => break,
            Incoming::Reply(bytes) => {
                let _ = tx.send(bytes).await;
                break;
            }
            Incoming::Query(query) => {
                // Certificate revoked, removed from the allowlist or expired since the handshake.
                if session.as_mut().is_some_and(|s| !s.still_permitted()) {
                    break;
                }
                let principal = session.as_ref().map(|s| s.principal.clone());
                let tx = tx.clone();
                let handler = Arc::clone(&handler);
                let ctx = RequestContext {
                    client,
                    transport: flavor.transport,
                    principal,
                    received_at: Instant::now(),
                };
                requests.spawn(async move {
                    let mut response = handler.handle(ctx, query.clone()).await;
                    if flavor.pad && query.edns.as_ref().is_some_and(Edns::has_padding) {
                        pad_response(&mut response);
                    }
                    if let Some(bytes) = encode_response(&query, &response, usize::from(u16::MAX)) {
                        let _ = tx.send(bytes).await;
                    }
                });
            }
        }
    }
    // Let in-flight requests finish (bounded by the drain time), then flush and close.
    let _ = timeout(limits.drain, async {
        while requests.join_next().await.is_some() {}
    })
    .await;
    drop(tx);
    let _ = writer_task.await;
}

/// Reads one length-prefixed frame. `None` for a clean close or a zero-length frame.
async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0_u8; 2];
    match reader.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = usize::from(u16::from_be_bytes(len));
    if len == 0 {
        return Ok(None);
    }
    let mut packet = vec![0_u8; len];
    reader.read_exact(&mut packet).await?;
    Ok(Some(packet))
}
