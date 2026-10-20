//! UDP listener.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dnsy_core::Transport;
use dnsy_engine::{Handler, RequestContext};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::query::{Incoming, encode_response, parse, udp_limit};

/// Largest query datagram accepted; anything at least this large is dropped.
const MAX_QUERY: usize = 4096;
/// In-flight requests per socket; excess datagrams are dropped (load shedding).
const MAX_IN_FLIGHT: usize = 1024;

pub(crate) async fn serve<H: Handler>(
    socket: UdpSocket,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
    drain: Duration,
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
        if n >= MAX_QUERY || tasks.len() >= MAX_IN_FLIGHT {
            continue;
        }
        let packet = buf[..n].to_vec();
        let socket = Arc::clone(&socket);
        let handler = Arc::clone(&handler);
        let received_at = Instant::now();
        tasks.spawn(async move {
            let reply = match parse(&packet) {
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
                    let Some(response) = handler.respond(ctx, query.clone()).await else {
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
