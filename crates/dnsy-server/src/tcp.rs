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
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::admission::{Activity, SlotLimit};
use crate::dot::mtls::ClientSession;
use crate::query::{Incoming, encode_response, pad_response, parse_admitted};

/// Concurrent requests per connection; the reader stops reading when reached (back-pressure).
const MAX_IN_FLIGHT_PER_CONN: usize = 32;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub idle: Duration,
    pub drain: Duration,
}

pub(crate) async fn serve<H: Handler>(
    listener: TcpListener,
    handler: Arc<H>,
    shutdown: watch::Receiver<bool>,
    limits: Limits,
    slots: Arc<SlotLimit>,
) {
    let wrap = |stream: TcpStream| std::future::ready(Some((stream, None)));
    serve_with(
        listener,
        handler,
        shutdown,
        limits,
        slots,
        Flavor::PLAIN,
        wrap,
    )
    .await;
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
    slots: Arc<SlotLimit>,
    flavor: Flavor,
    wrap: F,
) where
    H: Handler,
    S: AsyncRead + AsyncWrite + Send + 'static,
    F: Fn(TcpStream) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Option<(S, Option<ClientSession>)>> + Send,
{
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
        let handler = Arc::clone(&handler);
        let shutdown = shutdown.clone();
        let wrap = wrap.clone();
        let slots = Arc::clone(&slots);
        // The slot is taken in the connection task: recycling an idle connection can take a
        // moment, and the accept loop must keep serving everyone else meanwhile.
        conns.spawn(async move {
            let Some(permit) = slots.acquire_or_recycle(client.ip()).await else {
                tracing::debug!(%client, "tcp connection limit reached (shared or per client); closing");
                return; // dropping the stream closes it
            };
            // Answers are small frames; Nagle plus the peer's delayed ACK would hold each for ~40 ms.
            if let Err(e) = stream.set_nodelay(true) {
                tracing::debug!(%client, error = %e, "tcp set_nodelay failed");
            }
            let activity = permit.activity();
            // A handshake that stalls past the grace period can be recycled; one that finishes
            // withdraws any pending request in `establish`/`mark_authenticated` below.
            let wrapped = tokio::select! {
                () = activity.recycled() => None,
                wrapped = wrap(stream) => wrapped,
            };
            if let Some((stream, session)) = wrapped {
                if flavor.transport != Transport::Tcp {
                    activity.establish(); // TLS handshake done
                }
                if session.is_some() {
                    activity.mark_authenticated();
                }
                let link = Link { session, activity };
                connection(stream, client, link, handler, shutdown, limits, flavor).await;
            }
            drop(permit);
        });
    }
    let _ = timeout(limits.drain, async {
        while conns.join_next().await.is_some() {}
    })
    .await;
}

/// What a connection carries besides its socket: the mTLS session and its pool record.
struct Link {
    session: Option<ClientSession>,
    activity: Arc<Activity>,
}

async fn connection<H: Handler, S: AsyncRead + AsyncWrite + Send + 'static>(
    stream: S,
    client: SocketAddr,
    link: Link,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
    limits: Limits,
    flavor: Flavor,
) {
    let Link {
        mut session,
        activity,
    } = link;
    let (mut reader, writer) = tokio::io::split(stream);
    let (tx, rx) = mpsc::channel::<Vec<u8>>(MAX_IN_FLIGHT_PER_CONN);
    let idle = limits.idle;
    let writer_task = tokio::spawn(write_frames(writer, rx, idle));

    let mut recycled = false;
    let mut requests = JoinSet::new();
    loop {
        while requests.try_join_next().is_some() {}
        if requests.len() >= MAX_IN_FLIGHT_PER_CONN {
            requests.join_next().await;
        }
        // The whole frame must arrive within the idle time, so slow drip-feeding is cut off too.
        let frame = tokio::select! {
            _ = shutdown.changed() => break,
            () = activity.recycled() => {
                recycled = true;
                break;
            }
            frame = timeout(idle, read_frame(&mut reader)) => frame,
        };
        // Anything but a frame: peer closed, I/O error, empty frame or idle timeout.
        let Ok(Ok(Some(packet))) = frame else { break };
        activity.establish();
        activity.touch();
        match parse_admitted(&packet, &*handler, client, flavor.transport) {
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
                let busy = activity.begin();
                let ctx = RequestContext {
                    client,
                    transport: flavor.transport,
                    principal,
                    received_at: Instant::now(),
                };
                requests.spawn(async move {
                    let _busy = busy;
                    let Some(mut response) = handler.respond(ctx, query.clone()).await else {
                        return;
                    };
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
    if recycled {
        // Make room now: whatever is queued or half written is abandoned, so a peer that stopped
        // reading cannot hold the slot.
        writer_task.abort();
        requests.abort_all();
        return;
    }
    // Let in-flight requests finish (bounded by the drain time), then flush and close.
    let _ = timeout(limits.drain, async {
        while requests.join_next().await.is_some() {}
    })
    .await;
    drop(tx);
    let _ = writer_task.await;
}

/// Upper bound for the frames coalesced into one write.
const MAX_BATCH_BYTES: usize = 64 * 1024;

/// Appends `bytes` behind its 2-byte length prefix; oversized messages are skipped.
fn push_frame(out: &mut Vec<u8>, bytes: &[u8]) {
    if let Ok(len) = u16::try_from(bytes.len()) {
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes);
    }
}

/// Writer task: every frame leaves in a single write (prefix and body together, so no Nagle
/// stall), and answers that are already queued are sent in the same write.
async fn write_frames<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut rx: mpsc::Receiver<Vec<u8>>,
    idle: Duration,
) {
    let mut out = Vec::new();
    while let Some(first) = rx.recv().await {
        out.clear();
        push_frame(&mut out, &first);
        while out.len() < MAX_BATCH_BYTES {
            let Ok(next) = rx.try_recv() else { break };
            push_frame(&mut out, &next);
        }
        if out.is_empty() {
            continue;
        }
        if !matches!(timeout(idle, writer.write_all(&out)).await, Ok(Ok(()))) {
            break;
        }
    }
    let _ = writer.shutdown().await;
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

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll};

    use super::*;

    /// Records the size of every `poll_write` call.
    #[derive(Clone, Default)]
    struct CountingWriter(Arc<Mutex<Vec<usize>>>);

    impl AsyncWrite for CountingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.lock().unwrap().push(buf.len());
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn one_write_per_frame() {
        let writer = CountingWriter::default();
        let (tx, rx) = mpsc::channel(4);
        let task = tokio::spawn(write_frames(writer.clone(), rx, Duration::from_secs(1)));
        tx.send(vec![7; 40]).await.unwrap();
        // Let the writer finish the first frame before the next one is queued.
        while writer.0.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
        drop(tx);
        task.await.unwrap();
        assert_eq!(*writer.0.lock().unwrap(), vec![42]);
    }

    #[tokio::test]
    async fn queued_frames_share_one_write() {
        let writer = CountingWriter::default();
        let (tx, rx) = mpsc::channel(4);
        for n in [10_u8, 20, 30] {
            tx.send(vec![n; usize::from(n)]).await.unwrap();
        }
        drop(tx);
        write_frames(writer.clone(), rx, Duration::from_secs(1)).await;
        assert_eq!(*writer.0.lock().unwrap(), vec![10 + 20 + 30 + 6]);
    }

    #[tokio::test]
    async fn oversized_message_is_skipped() {
        let mut out = Vec::new();
        push_frame(&mut out, &vec![0; 70_000]);
        assert_eq!(out, Vec::<u8>::new());
    }

    fn query_frame() -> Vec<u8> {
        use dnsy_proto::{Class, Message, Name, Question, RecordType};
        let mut m = Message::response_to(&Message::decode(&[0; 12]).unwrap());
        m.header.qr = false;
        m.header.id = 7;
        m.questions.push(Question {
            name: Name::from_ascii("a.example.").unwrap(),
            qtype: RecordType::A,
            qclass: Class::In,
        });
        let bytes = m.encode(512).unwrap();
        let mut out = u16::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(&bytes);
        out
    }

    #[tokio::test]
    async fn recycled_connection_with_a_stalled_reader_is_released_at_once() {
        use dnsy_engine::RefusedHandler;
        let slots = SlotLimit::new_connections(1, 4);
        let slot = slots.try_acquire("192.0.2.1".parse().unwrap()).unwrap();
        let activity = slot.activity();
        // A tiny pipe that the peer never reads: the answer cannot be flushed.
        let (server_side, mut peer) = tokio::io::duplex(8);
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let limits = Limits {
            idle: Duration::from_secs(30),
            drain: Duration::from_secs(30),
        };
        let link = Link {
            session: None,
            activity,
        };
        let conn = tokio::spawn(async move {
            connection(
                server_side,
                "192.0.2.1:5353".parse().unwrap(),
                link,
                Arc::new(RefusedHandler),
                shutdown,
                limits,
                Flavor::PLAIN,
            )
            .await;
            drop(slot);
        });
        peer.write_all(&query_frame()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Another client needs the slot: the stalled connection must go within the bound.
        let taken = tokio::time::timeout(
            Duration::from_secs(2),
            slots.acquire_or_recycle("192.0.2.2".parse().unwrap()),
        )
        .await
        .expect("recycling completes");
        assert!(taken.is_some());
        tokio::time::timeout(Duration::from_secs(1), conn)
            .await
            .expect("the connection task ended without waiting for the flush")
            .unwrap();
    }

    #[tokio::test]
    async fn accept_loop_keeps_serving_while_a_recycle_is_pending() {
        use dnsy_engine::RefusedHandler;
        let slots = SlotLimit::new_connections(1, 4);
        // An established idle connection that never lets go of its slot.
        let stuck = slots.try_acquire("127.0.0.1".parse().unwrap()).unwrap();
        stuck.activity().establish();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown) = watch::channel(false);
        let limits = Limits {
            idle: Duration::from_secs(5),
            drain: Duration::from_millis(100),
        };
        let server = tokio::spawn(serve(
            listener,
            Arc::new(RefusedHandler),
            shutdown,
            limits,
            Arc::clone(&slots),
        ));
        let connect_from = |src: &'static str| async move {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.bind(format!("{src}:0").parse().unwrap()).unwrap();
            socket.connect(addr).await.unwrap()
        };
        // The first newcomer asks the stuck connection to close and waits for its slot.
        let _waiting = connect_from("127.0.0.2").await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        // The second one must be turned away at once, not after the first one's wait.
        let mut refused = connect_from("127.0.0.3").await;
        let mut buf = [0_u8; 1];
        let n = tokio::time::timeout(Duration::from_millis(250), refused.read(&mut buf))
            .await
            .expect("the accept loop was not blocked by the pending recycle")
            .unwrap_or(0);
        assert_eq!(n, 0);
        drop(stuck);
        let _ = shutdown_tx.send(true);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_stalled_handshake_past_grace_is_recycled() {
        use dnsy_engine::RefusedHandler;
        let slots = SlotLimit::new_connections(1, 4).with_establish_grace(Duration::ZERO);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown) = watch::channel(false);
        let limits = Limits {
            idle: Duration::from_secs(5),
            drain: Duration::from_millis(100),
        };
        // A handshake that takes far longer than the test waits.
        let slow = |stream: TcpStream| async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Some((stream, None))
        };
        let server = tokio::spawn(serve_with(
            listener,
            Arc::new(RefusedHandler),
            shutdown,
            limits,
            slots,
            Flavor::PLAIN,
            slow,
        ));
        let mut silent = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _newcomer = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0_u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), silent.read(&mut buf))
            .await
            .expect("the handshake reacted to the recycle request")
            .unwrap_or(0);
        assert_eq!(n, 0);
        let _ = shutdown_tx.send(true);
        server.await.unwrap();
    }
}
