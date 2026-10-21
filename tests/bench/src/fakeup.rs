//! A fast fake upstream: answers every A query with `192.0.2.1` (TTL `ttl`), `nx*` names with
//! NXDOMAIN. `tasks` tasks share one socket.

use std::net::SocketAddr;
use std::sync::Arc;

use dnsy_proto::{Class, Message, Name, RData, Rcode, Record, RecordType};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

fn answer(query: &Message, ttl: u32) -> Option<Vec<u8>> {
    let q = query.questions.first()?;
    let mut r = query.clone();
    r.header.qr = true;
    r.header.ra = true;
    r.edns = None;
    if q.name.to_string().starts_with("nx") {
        r.header.rcode = Rcode::NxDomain;
    } else {
        r.answers = vec![Record {
            name: Name::clone(&q.name),
            rtype: RecordType::A,
            class: Class::In,
            ttl,
            data: RData::A("192.0.2.1".parse().ok()?),
        }];
    }
    r.encode(512).ok()
}

/// Starts the upstream on `bind`; returns its address and the task handles.
pub async fn start(bind: SocketAddr, tasks: usize, ttl: u32) -> (SocketAddr, Vec<JoinHandle<()>>) {
    let socket = Arc::new(UdpSocket::bind(bind).await.expect("bind upstream"));
    let addr = socket.local_addr().expect("addr");
    let handles = (0..tasks.max(1))
        .map(|_| {
            let socket = Arc::clone(&socket);
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 4096];
                while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                    if let Some(out) = Message::decode(&buf[..n])
                        .ok()
                        .and_then(|q| answer(&q, ttl))
                    {
                        let _ = socket.send_to(&out, peer).await;
                    }
                }
            })
        })
        .collect();
    (addr, handles)
}
