//! UDP listener.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dnsy_core::Transport;
use dnsy_engine::{Handler, RequestContext};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::admission::SlotLimit;
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
        let packet = buf[..n].to_vec();
        let socket = Arc::clone(&socket);
        let handler = Arc::clone(&handler);
        let received_at = Instant::now();
        tasks.spawn(async move {
            let _slot = slot;
            let reply = match parse_admitted(&packet, &*handler, client, Transport::Udp) {
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
        });
    }
    let _ = tokio::time::timeout(drain, async { while tasks.join_next().await.is_some() {} }).await;
}
