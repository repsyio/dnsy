//! Listener tests. All sockets bind port 0.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use dnsy_engine::{Handler, RefusedHandler, RequestContext};
use dnsy_proto::{Class, Edns, Message, Name, Question, RData, Rcode, Record, RecordType};
use dnsy_server::{Server, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Answers with `answers` A records; a qname starting with `slow` is delayed.
struct Stub {
    answers: u8,
}

impl Handler for Stub {
    async fn handle(&self, _ctx: RequestContext, query: &Message) -> Message {
        let q = &query.questions[0];
        if q.name.to_string().starts_with("slow") {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        let mut r = Message::response_to(query);
        for i in 0..self.answers {
            r.answers.push(Record {
                name: q.name.clone(),
                rtype: RecordType::A,
                class: Class::In,
                ttl: 60,
                data: RData::A(Ipv4Addr::new(192, 0, 2, i)),
            });
        }
        r
    }
}

fn query(id: u16, name: &str, edns: Option<u16>) -> Message {
    let mut m = Message::response_to(&Message::decode(&[0; 12]).unwrap());
    m.header.qr = false;
    m.header.rd = true;
    m.header.id = id;
    m.questions.push(Question {
        name: Name::from_ascii(name).unwrap(),
        qtype: RecordType::A,
        qclass: Class::In,
    });
    m.edns = edns.map(|p| Edns {
        udp_payload: p,
        ..Edns::default()
    });
    m
}

fn config() -> ServerConfig {
    let lo = (Ipv4Addr::LOCALHOST, 0).into();
    let mut c = ServerConfig::new(vec![lo], vec![lo]);
    c.tcp_idle = Duration::from_millis(300);
    c
}

async fn udp_exchange(server: &Server, packet: &[u8]) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    sock.send_to(packet, server.udp_addrs()[0]).await.unwrap();
    let mut buf = vec![0; 65535];
    let n = tokio::time::timeout(Duration::from_millis(500), sock.recv(&mut buf))
        .await
        .ok()?
        .unwrap();
    buf.truncate(n);
    Some(buf)
}

async fn send_frame(s: &mut TcpStream, m: &Message) {
    let b = m.encode(65535).unwrap();
    s.write_all(&u16::try_from(b.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    s.write_all(&b).await.unwrap();
}

async fn read_frame(s: &mut TcpStream) -> Option<Message> {
    let mut len = [0; 2];
    s.read_exact(&mut len).await.ok()?;
    let mut buf = vec![0; usize::from(u16::from_be_bytes(len))];
    s.read_exact(&mut buf).await.ok()?;
    Some(Message::decode(&buf).unwrap())
}

#[tokio::test]
async fn udp_roundtrip_stub_handler() {
    let server = Server::start(config(), Arc::new(RefusedHandler))
        .await
        .unwrap();
    let q = query(7, "example.com.", None);
    let reply = udp_exchange(&server, &q.encode(512).unwrap())
        .await
        .unwrap();
    let r = Message::decode(&reply).unwrap();
    assert_eq!(r.header.id, 7);
    assert!(r.header.qr);
    assert_eq!(r.header.rcode, Rcode::Refused);
    assert_eq!(r.questions, q.questions);
    server.shutdown().await;
}

#[tokio::test]
async fn udp_truncates_for_512() {
    let server = Server::start(config(), Arc::new(Stub { answers: 100 }))
        .await
        .unwrap();
    let reply = udp_exchange(
        &server,
        &query(1, "big.example.", None).encode(512).unwrap(),
    )
    .await
    .unwrap();
    assert!(reply.len() <= 512);
    assert!(Message::decode(&reply).unwrap().header.tc);

    // A client advertising 4096 is still capped at 1232.
    let reply = udp_exchange(
        &server,
        &query(2, "big.example.", Some(4096)).encode(512).unwrap(),
    )
    .await
    .unwrap();
    assert!(reply.len() <= 1232);
    assert!(Message::decode(&reply).unwrap().header.tc);

    // Small answers fit and are not truncated.
    let small = Server::start(config(), Arc::new(Stub { answers: 2 }))
        .await
        .unwrap();
    let reply = udp_exchange(&small, &query(3, "s.example.", None).encode(512).unwrap())
        .await
        .unwrap();
    let r = Message::decode(&reply).unwrap();
    assert!(!r.header.tc);
    assert_eq!(r.answers.len(), 2);
    server.shutdown().await;
    small.shutdown().await;
}

#[tokio::test]
async fn udp_garbage_gets_formerr_or_drop() {
    let server = Server::start(config(), Arc::new(RefusedHandler))
        .await
        .unwrap();
    // Header readable, body garbage: FORMERR echoing the id.
    let mut bad = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    bad.extend_from_slice(&[0xff; 10]);
    let reply = udp_exchange(&server, &bad).await.unwrap();
    let r = Message::decode(&reply).unwrap();
    assert_eq!(r.header.id, 0x1234);
    assert_eq!(r.header.rcode, Rcode::FormErr);
    assert!(reply.len() <= bad.len() + 12, "no amplification");
    // Unreadable header, empty datagram and a stray response are dropped.
    assert!(udp_exchange(&server, &[1, 2, 3]).await.is_none());
    assert!(udp_exchange(&server, &[]).await.is_none());
    let mut resp = query(9, "x.example.", None);
    resp.header.qr = true;
    assert!(
        udp_exchange(&server, &resp.encode(512).unwrap())
            .await
            .is_none()
    );
    // Oversized datagram is dropped; the server keeps serving.
    assert!(udp_exchange(&server, &vec![0; 5000]).await.is_none());
    let ok = udp_exchange(&server, &query(5, "ok.example.", None).encode(512).unwrap()).await;
    assert!(ok.is_some());
    server.shutdown().await;
}

#[tokio::test]
async fn tcp_pipelined_queries() {
    let server = Server::start(config(), Arc::new(Stub { answers: 1 }))
        .await
        .unwrap();
    let mut s = TcpStream::connect(server.tcp_addrs()[0]).await.unwrap();
    send_frame(&mut s, &query(1, "slow.example.", None)).await;
    send_frame(&mut s, &query(2, "fast.example.", None)).await;
    let first = read_frame(&mut s).await.unwrap();
    let second = read_frame(&mut s).await.unwrap();
    assert_eq!((first.header.id, second.header.id), (2, 1), "out of order");
    server.shutdown().await;
}

#[tokio::test]
async fn tcp_idle_timeout_closes() {
    let server = Server::start(config(), Arc::new(RefusedHandler))
        .await
        .unwrap();
    let mut s = TcpStream::connect(server.tcp_addrs()[0]).await.unwrap();
    // Slowloris: a partial frame never completes.
    s.write_all(&[0x00, 0x20, 0x01]).await.unwrap();
    let mut buf = [0; 1];
    let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf))
        .await
        .expect("server closes the idle connection")
        .unwrap_or(0);
    assert_eq!(n, 0);
    server.shutdown().await;
}

#[tokio::test]
async fn tcp_connection_limit_and_garbage() {
    let mut c = config();
    c.max_tcp_conns = 1;
    let server = Server::start(c, Arc::new(RefusedHandler)).await.unwrap();
    let mut idle = TcpStream::connect(server.tcp_addrs()[0]).await.unwrap();
    establish(&mut idle).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    // The pool is full: the idle connection is recycled for the new one.
    let mut first = TcpStream::connect(server.tcp_addrs()[0]).await.unwrap();
    assert!(
        closed_within(&mut idle, Duration::from_secs(2)).await,
        "idle connection recycled"
    );
    // The new one works, and a garbage frame gets FORMERR then a close.
    send_frame(&mut first, &query(1, "a.example.", None)).await;
    assert_eq!(
        read_frame(&mut first).await.unwrap().header.rcode,
        Rcode::Refused
    );
    let mut bad = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
    let mut framed = u16::try_from(bad.len()).unwrap().to_be_bytes().to_vec();
    framed.append(&mut bad);
    first.write_all(&framed).await.unwrap();
    let r = read_frame(&mut first).await.unwrap();
    assert_eq!((r.header.id, r.header.rcode), (0xabcd, Rcode::FormErr));
    assert!(read_frame(&mut first).await.is_none());
    server.shutdown().await;
}

#[tokio::test]
async fn shutdown_drains() {
    let server = Server::start(config(), Arc::new(Stub { answers: 1 }))
        .await
        .unwrap();
    let mut s = TcpStream::connect(server.tcp_addrs()[0]).await.unwrap();
    send_frame(&mut s, &query(1, "slow.example.", None)).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let shutdown = tokio::spawn(server.shutdown());
    let r = read_frame(&mut s)
        .await
        .expect("in-flight request is answered");
    assert_eq!(r.header.id, 1);
    tokio::time::timeout(Duration::from_secs(5), shutdown)
        .await
        .unwrap()
        .unwrap();
}

/// Drops every query whose name starts with `drop` (as the engine does for ACL drop).
struct Dropper;

impl Handler for Dropper {
    fn handle(
        &self,
        _ctx: RequestContext,
        query: &Message,
    ) -> impl Future<Output = Message> + Send {
        std::future::ready(Message::response_to(query))
    }

    async fn respond(&self, ctx: RequestContext, query: &Message) -> Option<Message> {
        if query.questions[0].name.to_string().starts_with("drop") {
            None
        } else {
            Some(self.handle(ctx, query).await)
        }
    }
}

#[tokio::test]
async fn udp_drop_sends_no_reply() {
    let server = Server::start(config(), Arc::new(Dropper)).await.unwrap();
    let dropped = udp_exchange(
        &server,
        &query(1, "drop.example.", None).encode(512).unwrap(),
    )
    .await;
    assert!(dropped.is_none(), "dropped query must get no reply");
    let kept = udp_exchange(
        &server,
        &query(2, "keep.example.", None).encode(512).unwrap(),
    )
    .await;
    assert!(kept.is_some());
    server.shutdown().await;
}

#[tokio::test]
async fn tcp_drop_sends_no_reply_but_keeps_connection() {
    let server = Server::start(config(), Arc::new(Dropper)).await.unwrap();
    let mut s = TcpStream::connect(server.tcp_addrs()[0]).await.unwrap();
    send_frame(&mut s, &query(1, "drop.example.", None)).await;
    send_frame(&mut s, &query(2, "keep.example.", None)).await;
    let only = read_frame(&mut s).await.unwrap();
    assert_eq!(only.header.id, 2);
    server.shutdown().await;
}

/// Connects to `to` from the loopback address `from`.
async fn connect_from(from: &str, to: std::net::SocketAddr) -> TcpStream {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket
        .bind(std::net::SocketAddr::new(from.parse().unwrap(), 0))
        .unwrap();
    socket.connect(to).await.unwrap()
}

/// True when the server closed `s` (EOF or reset) within `wait`.
async fn establish(s: &mut TcpStream) {
    send_frame(s, &query(99, "warm.example.", None)).await;
    assert_eq!(read_frame(s).await.unwrap().header.id, 99);
}

async fn closed_within(s: &mut TcpStream, wait: Duration) -> bool {
    let mut buf = [0; 1];
    match tokio::time::timeout(wait, s.read(&mut buf)).await {
        Ok(r) => r.unwrap_or(0) == 0,
        Err(_) => false,
    }
}

#[tokio::test]
async fn tcp_cap_is_shared_across_listen_addresses() {
    let lo: std::net::SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut c = ServerConfig::new(vec![], vec![lo, lo]);
    c.tcp_idle = Duration::from_secs(10);
    c.max_tcp_conns = 1;
    let server = Server::start(c, Arc::new(RefusedHandler)).await.unwrap();
    let addrs = server.tcp_addrs().to_vec();
    assert_eq!(addrs.len(), 2);
    let mut first = TcpStream::connect(addrs[0]).await.unwrap();
    establish(&mut first).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut second = TcpStream::connect(addrs[1]).await.unwrap();
    // One pool: the second listener's connection recycles the first listener's idle one.
    assert!(closed_within(&mut first, Duration::from_secs(2)).await);
    assert!(!closed_within(&mut second, Duration::from_millis(200)).await);
    server.shutdown().await;
}

#[tokio::test]
async fn tcp_cap_recycles_oldest_idle_connection() {
    let mut c = config();
    c.tcp_idle = Duration::from_secs(10);
    c.max_tcp_conns = 2;
    let server = Server::start(c, Arc::new(RefusedHandler)).await.unwrap();
    let addr = server.tcp_addrs()[0];
    let mut oldest = TcpStream::connect(addr).await.unwrap();
    establish(&mut oldest).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut newer = TcpStream::connect(addr).await.unwrap();
    establish(&mut newer).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Using the older connection makes the other one the longest idle.
    send_frame(&mut oldest, &query(1, "a.example.", None)).await;
    assert_eq!(read_frame(&mut oldest).await.unwrap().header.id, 1);
    let mut third = TcpStream::connect(addr).await.unwrap();
    assert!(closed_within(&mut newer, Duration::from_secs(2)).await);
    for (id, s) in [(2, &mut oldest), (3, &mut third)] {
        send_frame(s, &query(id, "b.example.", None)).await;
        assert_eq!(read_frame(s).await.unwrap().header.id, id);
    }
    server.shutdown().await;
}

#[cfg_attr(
    target_os = "macos",
    ignore = "macOS has no loopback address besides 127.0.0.1"
)]
#[tokio::test]
async fn per_client_tcp_cap_leaves_room_for_other_clients() {
    let mut c = config();
    c.tcp_idle = Duration::from_secs(10);
    let server = Server::start(c, Arc::new(RefusedHandler)).await.unwrap();
    let addr = server.tcp_addrs()[0];
    let mut held = Vec::new();
    for _ in 0..16 {
        held.push(connect_from("127.0.0.2", addr).await);
    }
    let mut seventeenth = connect_from("127.0.0.2", addr).await;
    assert!(closed_within(&mut seventeenth, Duration::from_secs(2)).await);
    // Another client still gets in and is answered.
    let mut other = connect_from("127.0.0.3", addr).await;
    send_frame(&mut other, &query(5, "a.example.", None)).await;
    assert_eq!(read_frame(&mut other).await.unwrap().header.id, 5);
    // The first sixteen were not disturbed.
    for s in &mut held {
        assert!(!closed_within(s, Duration::from_millis(20)).await);
    }
    server.shutdown().await;
}

#[cfg_attr(
    target_os = "macos",
    ignore = "macOS has no loopback address besides 127.0.0.1"
)]
#[tokio::test]
async fn udp_per_client_in_flight_cap_keeps_other_clients_served() {
    let mut c = config();
    c.udp_in_flight = 4;
    c.udp_in_flight_per_client = 2;
    let server = Server::start(c, Arc::new(Stub { answers: 1 }))
        .await
        .unwrap();
    let target = server.udp_addrs()[0];
    let flooder = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let slow = query(1, "slow.example.", None).encode(512).unwrap();
    for _ in 0..20 {
        flooder.send_to(&slow, target).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    // A different source address is answered while the flooder holds its share.
    let other = UdpSocket::bind(("127.0.0.2", 0)).await.unwrap();
    other
        .send_to(
            &query(9, "fast.example.", None).encode(512).unwrap(),
            target,
        )
        .await
        .unwrap();
    let mut buf = vec![0; 1500];
    let n = tokio::time::timeout(Duration::from_millis(250), other.recv(&mut buf))
        .await
        .expect("other client is answered")
        .unwrap();
    assert_eq!(Message::decode(&buf[..n]).unwrap().header.id, 9);
    // The flooder got at most its share of answers.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut answered = 0;
    while flooder.try_recv(&mut buf).is_ok() {
        answered += 1;
    }
    assert!(answered <= 2, "flooder answered {answered} times");
    server.shutdown().await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn udp_sockets_per_address_binds_n_sockets() {
    let mut c = config();
    c.udp_sockets_per_address = 3;
    let server = Server::start(c, Arc::new(RefusedHandler)).await.unwrap();
    assert_eq!(server.udp_addrs().len(), 1);
    assert_eq!(server.udp_socket_count(), 3);
    assert_ne!(server.udp_addrs()[0].port(), 0);
    for id in 0..6 {
        let reply = udp_exchange(&server, &query(id, "a.example.", None).encode(512).unwrap())
            .await
            .unwrap();
        assert_eq!(Message::decode(&reply).unwrap().header.id, id);
    }
    server.shutdown().await;
}

#[tokio::test]
async fn bind_failure_names_protocol_address_and_override() {
    let taken = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = taken.local_addr().unwrap();
    let c = ServerConfig::new(Vec::new(), vec![addr]);
    let err = Server::start(c, Arc::new(RefusedHandler))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    let msg = err.to_string();
    assert!(msg.contains(&format!("tcp listener on {addr}")), "{msg}");
    assert!(msg.contains("DNSY_DNS__TCP"), "{msg}");

    let taken = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = taken.local_addr().unwrap();
    let c = ServerConfig::new(vec![addr], Vec::new());
    let msg = Server::start(c, Arc::new(RefusedHandler))
        .await
        .unwrap_err()
        .to_string();
    assert!(msg.contains(&format!("udp listener on {addr}")), "{msg}");
    assert!(msg.contains("DNSY_DNS__UDP"), "{msg}");
}
