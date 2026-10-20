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
    async fn handle(&self, _ctx: RequestContext, query: Message) -> Message {
        let q = &query.questions[0];
        if q.name.to_string().starts_with("slow") {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        let mut r = Message::response_to(&query);
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
    let mut first = TcpStream::connect(server.tcp_addrs()[0]).await.unwrap();
    let mut second = TcpStream::connect(server.tcp_addrs()[0]).await.unwrap();
    let mut buf = [0; 1];
    let n = tokio::time::timeout(Duration::from_secs(2), second.read(&mut buf))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0, "excess connection closed");
    // The first one still works, and a garbage frame gets FORMERR then a close.
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
    async fn handle(&self, _ctx: RequestContext, query: Message) -> Message {
        Message::response_to(&query)
    }

    async fn respond(&self, ctx: RequestContext, query: Message) -> Option<Message> {
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
