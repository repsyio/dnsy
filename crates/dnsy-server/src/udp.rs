//! UDP listener.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use dnsy_core::Transport;
use dnsy_engine::{Handler, RequestContext};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::admission::{Slot, SlotLimit};
use crate::query::{Incoming, encode_response, parse_admitted, udp_limit};

/// Largest query datagram accepted; anything at least this large is dropped.
const MAX_QUERY: usize = 4096;
/// Receive buffer requested for every UDP socket; the kernel may clamp it (`rmem_max`).
const RECV_BUFFER: usize = 4 * 1024 * 1024;

/// Binds `count` sockets to `addr`. More than one needs `SO_REUSEPORT` (Linux only; elsewhere a
/// single socket is bound). Port 0 is resolved by the first socket, the others join its port.
pub(crate) fn bind(addr: SocketAddr, count: usize) -> io::Result<Vec<UdpSocket>> {
    let count = if cfg!(target_os = "linux") {
        count.max(1)
    } else {
        1
    };
    let mut sockets = Vec::with_capacity(count);
    let mut target = addr;
    for _ in 0..count {
        let socket = Socket::new(
            Domain::for_address(target),
            Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        #[cfg(target_os = "linux")]
        if count > 1 {
            socket.set_reuse_port(true)?;
        }
        // Best effort: a kernel that refuses or clamps the size still works, just drops earlier.
        if let Err(e) = socket.set_recv_buffer_size(RECV_BUFFER) {
            tracing::debug!(error = %e, "udp set_recv_buffer_size failed");
        }
        socket.set_nonblocking(true)?;
        socket.bind(&target.into())?;
        let socket = UdpSocket::from_std(socket.into())?;
        target = socket.local_addr()?;
        sockets.push(socket);
    }
    Ok(sockets)
}

/// Polls `work` once. `Ok` when it completed in that poll, otherwise the future to keep
/// driving: the no-op waker is harmless because a task polls a spawned future again before it
/// sleeps, which registers the real waker.
fn poll_once<F: Future<Output = ()>>(mut work: Pin<Box<F>>) -> Result<(), Pin<Box<F>>> {
    match work.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(()) => Ok(()),
        Poll::Pending => Err(work),
    }
}

/// Answers one admitted datagram: runs the pipeline and sends the reply. Holds `slot` until done.
async fn answer<H: Handler>(
    socket: Arc<UdpSocket>,
    handler: Arc<H>,
    slot: Slot,
    incoming: Incoming,
    client: SocketAddr,
    received_at: Instant,
) {
    let _slot = slot;
    let reply = match incoming {
        Incoming::Drop => return,
        Incoming::Reply(bytes) => bytes,
        Incoming::Query(query) => {
            let limit = udp_limit(&query);
            let ctx = RequestContext {
                client,
                transport: Transport::Udp,
                principal: None,
                received_at,
            };
            let Some(response) = handler.respond(ctx, &query).await else {
                return;
            };
            match encode_response(&query, &response, limit) {
                Some(bytes) => bytes,
                None => return,
            }
        }
    };
    if let Err(e) = socket.send_to(&reply, client).await {
        tracing::debug!(error = %e, "udp send failed");
    }
}

pub(crate) async fn serve<H: Handler>(
    socket: UdpSocket,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
    drain: Duration,
    slots: Arc<SlotLimit>,
) {
    let socket = Arc::new(socket);
    let mut tasks = JoinSet::new();
    let mut buf = vec![0_u8; MAX_QUERY];
    loop {
        while tasks.try_join_next().is_some() {}
        let (n, client) = tokio::select! {
            _ = shutdown.changed() => break,
            received = socket.recv_from(&mut buf) => match received {
                Ok(r) => r,
                Err(e) => {
                    // e.g. ICMP-induced errors on some platforms; keep serving.
                    tracing::debug!(error = %e, "udp recv failed");
                    continue;
                }
            },
        };
        if n >= MAX_QUERY {
            continue;
        }
        // Load shedding: the shared pool bounds the work, the per-client share keeps one source
        // from taking all of it.
        let Some(slot) = slots.try_acquire(client.ip()) else {
            continue;
        };
        let incoming = parse_admitted(&buf[..n], &*handler, client, Transport::Udp);
        let work = Box::pin(answer(
            Arc::clone(&socket),
            Arc::clone(&handler),
            slot,
            incoming,
            client,
            Instant::now(),
        ));
        // A query the pipeline answers without waiting (a cache hit, a block, a local zone)
        // finishes in this one poll and never becomes a task; only a miss that has to wait for
        // an upstream is spawned, as the already boxed future.
        if let Err(pending) = poll_once(work) {
            tasks.spawn(pending);
        }
    }
    let _ = tokio::time::timeout(drain, async { while tasks.join_next().await.is_some() {} }).await;
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use dnsy_engine::RefusedHandler;
    use dnsy_proto::{Class, Header, Message, Name, Opcode, Question, Rcode, RecordType};

    use super::*;

    /// A handler that waits once before answering, like a cache miss waiting for an upstream.
    struct Slow;

    impl Handler for Slow {
        async fn handle(&self, ctx: RequestContext, query: &Message) -> Message {
            tokio::task::yield_now().await;
            RefusedHandler.handle(ctx, query).await
        }
    }

    fn query() -> Message {
        Message {
            header: Header {
                id: 7,
                qr: false,
                opcode: Opcode::Query,
                aa: false,
                tc: false,
                rd: true,
                ra: false,
                ad: false,
                cd: false,
                rcode: Rcode::NoError,
            },
            questions: vec![Question {
                name: Name::from_ascii("example.com.").unwrap(),
                qtype: RecordType::A,
                qclass: Class::In,
            }],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            edns: None,
        }
    }

    async fn pair() -> (Arc<UdpSocket>, UdpSocket, Arc<SlotLimit>) {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        (Arc::new(server), client, SlotLimit::new(8, 8))
    }

    #[tokio::test]
    async fn a_datagram_answered_without_waiting_is_finished_in_one_poll() {
        let (server, client, slots) = pair().await;
        let to = client.local_addr().unwrap();
        // A serving socket has long been registered as writable; a fresh one needs the reactor's
        // first event.
        server.writable().await.unwrap();
        let work = Box::pin(answer(
            Arc::clone(&server),
            Arc::new(RefusedHandler),
            slots.try_acquire(to.ip()).unwrap(),
            Incoming::Query(query()),
            to,
            Instant::now(),
        ));
        assert!(
            poll_once(work).is_ok(),
            "no task is needed for a ready answer"
        );
        let mut buf = [0_u8; 512];
        let (n, _) = client.recv_from(&mut buf).await.unwrap();
        let reply = Message::decode(&buf[..n]).unwrap();
        assert_eq!(reply.header.id, 7);
        assert_eq!(reply.header.rcode, Rcode::Refused);
    }

    #[tokio::test]
    async fn a_datagram_that_must_wait_is_handed_back_and_still_answered() {
        let (server, client, slots) = pair().await;
        let to = client.local_addr().unwrap();
        let work = Box::pin(answer(
            Arc::clone(&server),
            Arc::new(Slow),
            slots.try_acquire(to.ip()).unwrap(),
            Incoming::Query(query()),
            to,
            Instant::now(),
        ));
        let Err(pending) = poll_once(work) else {
            panic!("a waiting query cannot finish in one poll");
        };
        tokio::spawn(pending);
        let mut buf = [0_u8; 512];
        let (n, _) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(Message::decode(&buf[..n]).unwrap().header.id, 7);
    }
}
