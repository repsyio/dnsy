use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine as _;
use dnsy_proto::{
    Class, Edns, Header, Message, Name, Opcode, Question, RData, Rcode, Record, RecordType,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

use super::*;

fn query(name: &str) -> Message {
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
            name: Name::from_ascii(name).unwrap(),
            qtype: RecordType::A,
            qclass: Class::In,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
        edns: None,
    }
}

fn answer(q: &Message) -> Message {
    let mut r = Message::response_to(q);
    r.answers.push(Record {
        name: q.questions[0].name.clone(),
        rtype: RecordType::A,
        class: Class::In,
        ttl: 60,
        data: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    });
    r
}

fn client(timeout_ms: u64) -> UpstreamClient {
    UpstreamClient::new(UpstreamConfig {
        timeout: Duration::from_millis(timeout_ms),
        ..UpstreamConfig::default()
    })
    .unwrap()
}

fn up(transport: UpstreamTransport, port: u16) -> Upstream {
    Upstream {
        transport,
        host: "127.0.0.1".into(),
        port,
        sni: None,
        spki_pin: None,
    }
}

/// Spawns a UDP server; `f` returns the datagrams to send back for each received query.
async fn udp_server<F>(f: F) -> (u16, tokio::task::JoinHandle<()>)
where
    F: Fn(Message) -> Vec<Vec<u8>> + Send + 'static,
{
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let h = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let Ok(q) = Message::decode(&buf[..n]) else {
                continue;
            };
            for d in f(q) {
                sock.send_to(&d, peer).await.unwrap();
            }
        }
    });
    (port, h)
}

fn enc(m: &Message) -> Vec<u8> {
    m.encode(4096).unwrap()
}

async fn serve_framed<S>(stream: &mut S, handler: &(impl Fn(Message) -> Message + ?Sized))
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    loop {
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).await.is_err() {
            return;
        }
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
        if stream.read_exact(&mut body).await.is_err() {
            return;
        }
        let resp = enc(&handler(Message::decode(&body).unwrap()));
        let mut out = u16::try_from(resp.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(&resp);
        if stream.write_all(&out).await.is_err() {
            return;
        }
    }
}

#[tokio::test]
async fn udp_answer() {
    let (port, _h) = udp_server(|q| vec![enc(&answer(&q))]).await;
    let resp = client(1000)
        .query(&up(UpstreamTransport::Udp, port), &query("example.com."))
        .await
        .unwrap();
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(resp.header.rcode, Rcode::NoError);
}

#[tokio::test]
async fn ids_are_random_and_edns_advertised() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (port, _h) = udp_server(move |q| {
        tx.send(q.clone()).unwrap();
        vec![enc(&answer(&q))]
    })
    .await;
    let c = client(1000);
    let u = up(UpstreamTransport::Udp, port);
    let mut ids = std::collections::HashSet::new();
    for _ in 0..16 {
        c.query(&u, &query("example.com.")).await.unwrap();
        let seen = rx.recv().await.unwrap();
        assert_eq!(seen.edns.unwrap().udp_payload, 1232);
        ids.insert(seen.header.id);
    }
    assert!(ids.len() > 8, "ids not random: {ids:?}");
    assert!(!ids.contains(&7) || ids.len() > 1);
}

#[tokio::test]
async fn do_and_cd_bits_forwarded() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (port, _h) = udp_server(move |q| {
        tx.send(q.clone()).unwrap();
        vec![enc(&answer(&q))]
    })
    .await;
    let c = client(1000);
    let u = up(UpstreamTransport::Udp, port);

    let mut q = query("example.com.");
    q.header.cd = true;
    q.edns = Some(Edns {
        dnssec_ok: true,
        udp_payload: 4096,
        ..Edns::default()
    });
    c.query(&u, &q).await.unwrap();
    let seen = rx.recv().await.unwrap();
    assert!(seen.header.cd);
    let e = seen.edns.unwrap();
    assert!(e.dnssec_ok);
    assert_eq!(e.udp_payload, 1232);

    c.query(&u, &query("example.com.")).await.unwrap();
    let seen = rx.recv().await.unwrap();
    assert!(!seen.header.cd);
    assert!(!seen.edns.unwrap().dnssec_ok);
}

#[tokio::test]
async fn mismatched_id_ignored() {
    let (port, _h) = udp_server(|q| {
        let mut wrong_id = answer(&q);
        wrong_id.header.id = q.header.id.wrapping_add(1);
        let mut wrong_q = answer(&q);
        wrong_q.questions[0].name = Name::from_ascii("evil.example.").unwrap();
        let mut not_response = answer(&q);
        not_response.header.qr = false;
        vec![
            enc(&wrong_id),
            enc(&wrong_q),
            enc(&not_response),
            vec![1, 2, 3],
            enc(&answer(&q)),
        ]
    })
    .await;
    let resp = client(1000)
        .query(&up(UpstreamTransport::Udp, port), &query("example.com."))
        .await
        .unwrap();
    assert_eq!(
        resp.questions[0].name,
        Name::from_ascii("example.com.").unwrap()
    );
}

#[tokio::test]
async fn only_spoofed_responses_time_out() {
    let (port, _h) = udp_server(|q| {
        let mut wrong = answer(&q);
        wrong.header.id = q.header.id.wrapping_add(1);
        vec![enc(&wrong)]
    })
    .await;
    let err = client(200)
        .query(&up(UpstreamTransport::Udp, port), &query("example.com."))
        .await
        .unwrap_err();
    assert!(matches!(err, UpstreamError::Timeout), "{err}");
}

#[tokio::test]
async fn timeout_errors() {
    let (port, _h) = udp_server(|_| vec![]).await;
    let err = client(100)
        .query(&up(UpstreamTransport::Udp, port), &query("example.com."))
        .await
        .unwrap_err();
    assert!(matches!(err, UpstreamError::Timeout), "{err}");
}

#[tokio::test]
async fn tc_triggers_tcp_retry() {
    // UDP and TCP on the same port; retry binding until a free pair is found.
    let (udp, tcp) = loop {
        let t = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = t.local_addr().unwrap().port();
        if let Ok(u) = UdpSocket::bind(("127.0.0.1", port)).await {
            break (u, t);
        }
    };
    let port = tcp.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
            let q = Message::decode(&buf[..n]).unwrap();
            let mut r = Message::response_to(&q);
            r.header.tc = true;
            udp.send_to(&enc(&r), peer).await.unwrap();
        }
    });
    tokio::spawn(async move {
        loop {
            let (mut s, _) = tcp.accept().await.unwrap();
            tokio::spawn(async move { serve_framed(&mut s, &|q| answer(&q)).await });
        }
    });
    let resp = client(1000)
        .query(&up(UpstreamTransport::Udp, port), &query("example.com."))
        .await
        .unwrap();
    assert!(!resp.header.tc);
    assert_eq!(resp.answers.len(), 1);
}

#[tokio::test]
async fn tcp_answer_and_mismatch() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                serve_framed(&mut s, &|q| {
                    let mut r = answer(&q);
                    if q.questions[0].name == Name::from_ascii("bad.example.").unwrap() {
                        r.header.id = r.header.id.wrapping_add(1);
                    }
                    r
                })
                .await;
            });
        }
    });
    let c = client(1000);
    let u = up(UpstreamTransport::Tcp, port);
    assert_eq!(
        c.query(&u, &query("example.com."))
            .await
            .unwrap()
            .answers
            .len(),
        1
    );
    let err = c.query(&u, &query("bad.example.")).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Mismatch), "{err}");
}

#[tokio::test]
async fn query_without_question_rejected() {
    let mut q = query("example.com.");
    q.questions.clear();
    let err = client(100)
        .query(&up(UpstreamTransport::Udp, 9), &q)
        .await
        .unwrap_err();
    assert!(matches!(err, UpstreamError::NoQuestion));
}

struct TestPki {
    ca_der: CertificateDer<'static>,
    spki_pin: [u8; 32],
    server_cfg: Arc<rustls::ServerConfig>,
}

fn pki() -> TestPki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["dns.test".to_owned()])
        .unwrap()
        .signed_by(&key, &rcgen::Issuer::new(ca_params, ca_key))
        .unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .unwrap();
    let spki_pin = ring::digest::digest(
        &ring::digest::SHA256,
        &rcgen::PublicKeyData::subject_public_key_info(&key),
    )
    .as_ref()
    .try_into()
    .unwrap();
    TestPki {
        ca_der: ca.der().clone(),
        spki_pin,
        server_cfg: Arc::new(cfg),
    }
}

async fn dot_server(cfg: Arc<rustls::ServerConfig>) -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let n = accepts.clone();
    let acceptor = TlsAcceptor::from(cfg);
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            n.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut t) = acceptor.accept(s).await {
                    serve_framed(&mut t, &|q| answer(&q)).await;
                }
            });
        }
    });
    (port, accepts)
}

fn dot_client(pki: &TestPki, idle_ms: u64) -> UpstreamClient {
    UpstreamClient::new(UpstreamConfig {
        timeout: Duration::from_secs(5),
        dot_idle: Duration::from_millis(idle_ms),
        tls_roots: TlsRoots::Custom(vec![pki.ca_der.clone()]),
        ..UpstreamConfig::default()
    })
    .unwrap()
}

fn dot_up(port: u16) -> Upstream {
    "tls://127.0.0.1:1#dns.test"
        .parse::<Upstream>()
        .map(|u| Upstream { port, ..u })
        .unwrap()
}

#[tokio::test]
async fn dot_with_test_ca() {
    let pki = pki();
    let (port, _) = dot_server(pki.server_cfg.clone()).await;
    let resp = dot_client(&pki, 30_000)
        .query(&dot_up(port), &query("example.com."))
        .await
        .unwrap();
    assert_eq!(resp.answers.len(), 1);
}

#[tokio::test]
async fn dot_reuses_connection() {
    let pki = pki();
    let (port, accepts) = dot_server(pki.server_cfg.clone()).await;
    let c = dot_client(&pki, 30_000);
    for _ in 0..3 {
        c.query(&dot_up(port), &query("example.com."))
            .await
            .unwrap();
    }
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dot_idle_connection_is_closed_and_replaced() {
    let pki = pki();
    let (port, accepts) = dot_server(pki.server_cfg.clone()).await;
    let c = dot_client(&pki, 50);
    c.query(&dot_up(port), &query("example.com."))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;
    c.query(&dot_up(port), &query("example.com."))
        .await
        .unwrap();
    assert_eq!(accepts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn dot_untrusted_or_wrong_name_rejected() {
    let pki = pki();
    let (port, _) = dot_server(pki.server_cfg.clone()).await;
    // Default (webpki) roots do not trust the test CA.
    let c = client(2000);
    let err = c
        .query(&dot_up(port), &query("example.com."))
        .await
        .unwrap_err();
    assert!(matches!(err, UpstreamError::Tls(_)), "{err}");
    // Trusted CA but the certificate is not valid for this name.
    let mut u = dot_up(port);
    u.sni = Some("other.test".into());
    let err = dot_client(&pki, 1000)
        .query(&u, &query("example.com."))
        .await
        .unwrap_err();
    assert!(matches!(err, UpstreamError::Tls(_)), "{err}");
}

#[test]
fn parse_upstreams() {
    let u: Upstream = "udp://9.9.9.9".parse().unwrap();
    assert_eq!((u.transport, u.port), (UpstreamTransport::Udp, 53));
    let u: Upstream = "tcp://[2001:db8::1]:5353".parse().unwrap();
    assert_eq!((u.host.as_str(), u.port), ("2001:db8::1", 5353));
    assert_eq!(u.to_string(), "tcp://[2001:db8::1]:5353");
    let u: Upstream = "tls://1.1.1.1#cloudflare-dns.com".parse().unwrap();
    assert_eq!((u.port, u.server_name()), (853, "cloudflare-dns.com"));
    assert_eq!(u.to_string(), "tls://1.1.1.1:853#cloudflare-dns.com");
    let u: Upstream = "tls://dns.example".parse().unwrap();
    assert_eq!(u.server_name(), "dns.example");
    for bad in [
        "9.9.9.9",
        "http://x",
        "udp://",
        "udp://h:0",
        "udp://h:x",
        "udp://h#sni",
        "tls://h#",
        "udp://[::1",
        "udp://[::1]x",
        "udp://h/p",
    ] {
        assert!(bad.parse::<Upstream>().is_err(), "{bad}");
    }
}

/// Like [`udp_server`], with the client's address and mutable state.
async fn udp_server_peers<F>(mut f: F) -> u16
where
    F: FnMut(Message, SocketAddr) -> Vec<Vec<u8>> + Send + 'static,
{
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let Ok(q) = Message::decode(&buf[..n]) else {
                continue;
            };
            for d in f(q, peer) {
                sock.send_to(&d, peer).await.unwrap();
            }
        }
    });
    port
}

/// Source ports seen by a server answering every query.
async fn port_recorder() -> (u16, mpsc::UnboundedReceiver<u16>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let port = udp_server_peers(move |q, peer| {
        tx.send(peer.port()).unwrap();
        vec![enc(&answer(&q))]
    })
    .await;
    (port, rx)
}

#[tokio::test]
async fn pooled_sockets_use_random_ports_and_rotate() {
    let (port, mut rx) = port_recorder().await;
    let mut c = client(1000);
    c.rotation.queries = 3;
    let u = up(UpstreamTransport::Udp, port);
    let mut ports = Vec::new();
    for _ in 0..7 {
        c.query(&u, &query("example.com.")).await.unwrap();
        ports.push(rx.recv().await.unwrap());
    }
    // Reused for three queries, then replaced by a socket on another port.
    assert_eq!(
        (ports[0], ports[1], ports[2]),
        (ports[0], ports[0], ports[0])
    );
    assert_eq!(
        (ports[3], ports[4], ports[5]),
        (ports[3], ports[3], ports[3])
    );
    assert_ne!(ports[0], ports[3]);
    assert_ne!(ports[3], ports[6]);

    // Rotation by age.
    c.rotation = Rotation {
        queries: u32::MAX,
        age: Duration::from_millis(50),
        idle: Duration::from_secs(60),
    };
    c.query(&u, &query("example.com.")).await.unwrap();
    let before = rx.recv().await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    c.query(&u, &query("example.com.")).await.unwrap();
    assert_ne!(rx.recv().await.unwrap(), before);

    // Every new socket gets an OS-randomised port, not the next one up.
    c.rotation.queries = 1;
    let mut fresh = Vec::new();
    for _ in 0..16 {
        c.query(&u, &query("example.com.")).await.unwrap();
        fresh.push(rx.recv().await.unwrap());
    }
    let distinct: std::collections::HashSet<_> = fresh.iter().collect();
    assert!(distinct.len() >= 12, "ports repeat: {fresh:?}");
    let sequential = fresh
        .windows(2)
        .filter(|w| w[1] == w[0].wrapping_add(1))
        .count();
    assert!(sequential < 4, "ports look sequential: {fresh:?}");
}

#[tokio::test]
async fn pooled_socket_ignores_late_answer_to_earlier_query() {
    // The second query (same question) first gets a replay of the first answer, whose id is the
    // first query's: the full match on the reused socket must skip it.
    let mut first: Option<Message> = None;
    let port = udp_server_peers(move |q, _| {
        let a = answer(&q);
        match first.take() {
            None => {
                first = Some(a.clone());
                vec![enc(&a)]
            }
            Some(old) => {
                let mut stale_q = answer(&q);
                stale_q.questions[0].qtype = RecordType::Aaaa;
                vec![enc(&old), enc(&stale_q), enc(&a)]
            }
        }
    })
    .await;
    let c = client(1000);
    let u = up(UpstreamTransport::Udp, port);
    let r1 = c.query(&u, &query("example.com.")).await.unwrap();
    let r2 = c.query(&u, &query("example.com.")).await.unwrap();
    assert_ne!(r1.header.id, r2.header.id);
    assert_eq!(r2.questions[0].qtype, RecordType::A);
    assert_eq!(c.udp_state()[&u].idle.len(), 1, "one socket served both");
}

#[tokio::test]
async fn timed_out_socket_is_not_pooled() {
    let mut n = 0;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let port = udp_server_peers(move |q, peer| {
        n += 1;
        tx.send(peer.port()).unwrap();
        // The first query goes unanswered.
        if n == 1 {
            vec![]
        } else {
            vec![enc(&answer(&q))]
        }
    })
    .await;
    let c = client(100);
    let u = up(UpstreamTransport::Udp, port);
    let err = c.query(&u, &query("example.com.")).await.unwrap_err();
    assert!(matches!(err, UpstreamError::Timeout), "{err}");
    assert!(c.udp_state()[&u].idle.is_empty());
    c.query(&u, &query("example.com.")).await.unwrap();
    assert_ne!(rx.recv().await.unwrap(), rx.recv().await.unwrap());
}

#[tokio::test]
async fn concurrent_queries_get_separate_sockets_and_pool_is_bounded() {
    let (port, mut rx) = port_recorder().await;
    let c = Arc::new(client(1000));
    let u = up(UpstreamTransport::Udp, port);
    let tasks: Vec<_> = (0..64)
        .map(|i| {
            let (c, u) = (Arc::clone(&c), u.clone());
            tokio::spawn(async move {
                let name = format!("n{i}.example.com.");
                let r = c.query(&u, &query(&name)).await.unwrap();
                assert_eq!(r.questions[0].name, Name::from_ascii(&name).unwrap());
            })
        })
        .collect();
    for t in tasks {
        t.await.unwrap();
    }
    let mut ports = std::collections::HashSet::new();
    while let Ok(p) = rx.try_recv() {
        ports.insert(p);
    }
    assert!(ports.len() > 1, "concurrent queries shared one socket");
    let idle = c.udp_state()[&u].idle.len();
    assert!((1..=UDP_POOL_IDLE).contains(&idle), "{idle}");
}

#[tokio::test]
async fn receive_buffer_is_reused_and_sized() {
    let (port, _rx) = port_recorder().await;
    let c = client(1000);
    let u = up(UpstreamTransport::Udp, port);
    c.query(&u, &query("example.com.")).await.unwrap();
    let ptr = {
        let state = c.udp_state();
        let conn = &state[&u].idle[0];
        assert_eq!(conn.buf.len(), MAX_UDP_RESPONSE);
        conn.buf.as_ptr()
    };
    c.query(&u, &query("example.com.")).await.unwrap();
    assert_eq!(c.udp_state()[&u].idle[0].buf.as_ptr(), ptr);
}

#[tokio::test]
async fn upstream_address_is_cached() {
    let (port, _rx) = port_recorder().await;
    let c = client(1000);
    let literal = up(UpstreamTransport::Udp, port);
    c.query(&literal, &query("example.com.")).await.unwrap();
    let r = c.udp_state()[&literal].resolved.unwrap();
    assert_eq!((r.addr.port(), r.until), (port, None));

    let named = Upstream {
        host: "localhost".into(),
        ..literal
    };
    let addr = c.resolve(&named).await.unwrap();
    assert_eq!(addr.port(), port);
    let until = c.udp_state()[&named].resolved.unwrap().until.unwrap();
    assert!(until > Instant::now() && until <= Instant::now() + RESOLVE_TTL);
}

#[tokio::test]
async fn pooled_socket_never_outlives_rotation_count_age_or_idle_lifetime() {
    let (port, mut rx) = port_recorder().await;
    let mut c = client(1000);
    let u = up(UpstreamTransport::Udp, port);
    // Default count: no port serves more than UDP_ROTATE_QUERIES queries.
    let mut ports = Vec::new();
    for _ in 0..UDP_ROTATE_QUERIES * 3 {
        c.query(&u, &query("example.com.")).await.unwrap();
        ports.push(rx.recv().await.unwrap());
    }
    let runs: Vec<usize> = ports.chunk_by(|a, b| a == b).map(<[u16]>::len).collect();
    assert!(
        runs.iter().all(|&n| n <= UDP_ROTATE_QUERIES as usize),
        "{runs:?}"
    );
    assert_eq!(runs.len(), 3, "{runs:?}");
    const { assert!(UDP_ROTATE_QUERIES <= 16 && UDP_ROTATE_AGE.as_secs() <= 5) };

    // Idle lifetime: a socket parked longer than it is closed.
    c.rotation.idle = Duration::from_millis(50);
    c.query(&u, &query("example.com.")).await.unwrap();
    let before = rx.recv().await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    c.query(&u, &query("example.com.")).await.unwrap();
    assert_ne!(rx.recv().await.unwrap(), before);
}

#[tokio::test]
async fn answer_from_wrong_source_is_rejected() {
    // A valid-looking answer (right ID and question) sent to the client's port from another
    // socket must not be accepted: the pooled socket is connected to the upstream.
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let spoofer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = server.recv_from(&mut buf).await {
            let q = Message::decode(&buf[..n]).unwrap();
            let mut forged = answer(&q);
            forged.answers[0].data = RData::A(Ipv4Addr::new(198, 51, 100, 66));
            spoofer.send_to(&enc(&forged), peer).await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            server.send_to(&enc(&answer(&q)), peer).await.unwrap();
        }
    });
    let c = client(1000);
    let u = up(UpstreamTransport::Udp, port);
    for _ in 0..3 {
        let r = c.query(&u, &query("example.com.")).await.unwrap();
        assert_eq!(r.answers[0].data, RData::A(Ipv4Addr::new(192, 0, 2, 1)));
    }
}

#[tokio::test]
async fn question_is_matched_case_sensitively() {
    let (port, _h) = udp_server(|q| {
        let mut recased = answer(&q);
        recased.questions[0].name = Name::from_ascii("EXAMPLE.com.").unwrap();
        recased.answers[0].data = RData::A(Ipv4Addr::new(198, 51, 100, 66));
        vec![enc(&recased), enc(&answer(&q))]
    })
    .await;
    let r = client(1000)
        .query(&up(UpstreamTransport::Udp, port), &query("example.com."))
        .await
        .unwrap();
    assert_eq!(r.questions[0].name.as_wire(), b"\x07example\x03com\x00");
    assert_eq!(r.answers[0].data, RData::A(Ipv4Addr::new(192, 0, 2, 1)));
}

#[tokio::test]
async fn datagrams_queued_while_pooled_are_discarded_before_reuse() {
    let (port, _rx) = port_recorder().await;
    let c = client(1000);
    let u = up(UpstreamTransport::Udp, port);
    c.query(&u, &query("example.com.")).await.unwrap();
    let mut conn = c.udp_state().get_mut(&u).unwrap().idle.pop().unwrap();
    // A datagram sprayed at the parked socket's port from another address.
    let forger = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    forger
        .send_to(b"x", conn.socket.local_addr().unwrap())
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    // Only the connected peer gets through the kernel filter; the stray one was dropped there.
    assert_eq!(conn.drain().unwrap(), 0);
    c.put_udp(&u, conn);

    // Late answers from the upstream itself do queue up; they are discarded on reuse.
    let (tx, mut rx) = mpsc::unbounded_channel::<SocketAddr>();
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sport = server.local_addr().unwrap().port();
    let server = Arc::new(server);
    let s2 = Arc::clone(&server);
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = s2.recv_from(&mut buf).await {
            let q = Message::decode(&buf[..n]).unwrap();
            tx.send(peer).unwrap();
            s2.send_to(&enc(&answer(&q)), peer).await.unwrap();
        }
    });
    let u2 = up(UpstreamTransport::Udp, sport);
    c.query(&u2, &query("example.com.")).await.unwrap();
    let peer = rx.recv().await.unwrap();
    for _ in 0..3 {
        server.send_to(b"late", peer).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut conn = c.udp_state().get_mut(&u2).unwrap().idle.pop().unwrap();
    assert_eq!(conn.drain().unwrap(), 3);
    assert_eq!(conn.drain().unwrap(), 0);
}

const LONG: &str = "abcdefghijklmnopqrstuvwxyz.example.";

fn case_client(own_addrs: Vec<std::net::SocketAddr>) -> UpstreamClient {
    UpstreamClient::new(UpstreamConfig {
        timeout: Duration::from_millis(400),
        case_randomization: true,
        own_addrs,
        ..UpstreamConfig::default()
    })
    .unwrap()
}

/// A server that records the question bytes it receives; `lower` makes it answer in lower case.
async fn recording_server(
    lower: bool,
) -> (
    u16,
    Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    tokio::task::JoinHandle<()>,
) {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    let (port, h) = udp_server(move |q| {
        log.lock()
            .unwrap()
            .push(q.questions[0].name.as_wire().to_vec());
        let mut r = answer(&q);
        if lower {
            r.questions[0].name = q.questions[0].name.to_lowercase();
            r.answers[0].name = q.questions[0].name.to_lowercase();
        }
        vec![enc(&r)]
    })
    .await;
    (port, seen, h)
}

#[tokio::test]
async fn case_randomization_sends_mixed_case_and_restores_it() {
    let (port, seen, _h) = recording_server(false).await;
    let c = case_client(vec![]);
    let u = up(UpstreamTransport::Udp, port);
    for _ in 0..4 {
        let resp = c.query(&u, &query(LONG)).await.unwrap();
        assert_eq!(
            resp.questions[0].name.as_wire(),
            query(LONG).questions[0].name.as_wire()
        );
        assert_eq!(
            resp.answers[0].name.as_wire(),
            query(LONG).questions[0].name.as_wire()
        );
    }
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 4);
    assert!(seen.iter().any(|w| w.iter().any(u8::is_ascii_uppercase)));
}

#[tokio::test]
async fn case_randomization_off_by_default() {
    let (port, seen, _h) = recording_server(false).await;
    client(400)
        .query(&up(UpstreamTransport::Udp, port), &query(LONG))
        .await
        .unwrap();
    assert!(!seen.lock().unwrap()[0].iter().any(u8::is_ascii_uppercase));
}

#[tokio::test]
async fn case_randomization_falls_back_for_lowercasing_upstream() {
    let (port, seen, _h) = recording_server(true).await;
    let c = case_client(vec![]);
    let u = up(UpstreamTransport::Udp, port);
    let resp = c.query(&u, &query(LONG)).await.unwrap();
    assert_eq!(resp.answers.len(), 1);
    // Probe, then the plain retry.
    assert_eq!(seen.lock().unwrap().len(), 2);
    // Remembered: the next query goes out once, in the caller's case.
    c.query(&u, &query(LONG)).await.unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[2], query(LONG).questions[0].name.as_wire());
}

#[tokio::test]
async fn case_randomization_falls_back_over_tcp() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                serve_framed(&mut s, &|q| {
                    let mut r = answer(&q);
                    r.questions[0].name = q.questions[0].name.to_lowercase();
                    r
                })
                .await;
            });
        }
    });
    let resp = case_client(vec![])
        .query(&up(UpstreamTransport::Tcp, port), &query(LONG))
        .await
        .unwrap();
    assert_eq!(resp.answers.len(), 1);
}

#[tokio::test]
async fn case_fallback_expires() {
    let (port, seen, _h) = recording_server(true).await;
    let c = case_client(vec![]);
    let u = up(UpstreamTransport::Udp, port);
    c.query(&u, &query(LONG)).await.unwrap();
    c.no_case_state().insert(u.clone(), Instant::now());
    c.query(&u, &query(LONG)).await.unwrap();
    // Probed again (and fell back again): 2 + 2 datagrams.
    assert_eq!(seen.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn dot_spki_pin_match_and_mismatch() {
    let pki = pki();
    let (port, _) = dot_server(pki.server_cfg.clone()).await;
    let mut u = dot_up(port);
    u.spki_pin = Some(pki.spki_pin);
    dot_client(&pki, 1000)
        .query(&u, &query("example.com."))
        .await
        .unwrap();
    u.spki_pin = Some([7; 32]);
    let err = dot_client(&pki, 1000)
        .query(&u, &query("example.com."))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, UpstreamError::Tls(m) if m.contains("pin")),
        "{err}"
    );
}

#[test]
fn spki_pin_parses_and_round_trips() {
    let pin = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    let s = format!("tls://1.1.1.1:853?pin-sha256={pin}#cloudflare-dns.com");
    let u: Upstream = s.parse().unwrap();
    assert_eq!(u.spki_pin, Some([9; 32]));
    assert_eq!(u.to_string(), s);
    for bad in [
        "tls://h?pin-sha256=AAAA",
        "tls://h?other=1",
        "udp://h?pin-sha256=x",
    ] {
        assert!(bad.parse::<Upstream>().is_err(), "{bad}");
    }
}

#[test]
fn spki_hash_ignores_garbage() {
    assert_eq!(spki::spki_sha256(&[]), None);
    assert_eq!(spki::spki_sha256(&[0x30, 0x03, 1, 2, 3]), None);
}

#[tokio::test]
async fn loop_guard_refuses_own_addresses() {
    let (port, seen, _h) = recording_server(false).await;
    let up_local = up(UpstreamTransport::Udp, port);
    for own in [
        vec![([127, 0, 0, 1], port).into()],
        vec![([0, 0, 0, 0], port).into()],
    ] {
        let err = case_client(own)
            .query(&up_local, &query(LONG))
            .await
            .unwrap_err();
        assert!(matches!(err, UpstreamError::Loop(_)), "{err}");
    }
    // A host name that resolves to our own address is refused too.
    let named = Upstream {
        host: "localhost".into(),
        ..up_local.clone()
    };
    let own = vec![([0, 0, 0, 0], port).into()];
    let err = case_client(own)
        .query(&named, &query(LONG))
        .await
        .unwrap_err();
    assert!(matches!(err, UpstreamError::Loop(_)), "{err}");
    assert!(seen.lock().unwrap().is_empty());
    // Another port is fine.
    case_client(vec![([127, 0, 0, 1], 1).into()])
        .query(&up_local, &query(LONG))
        .await
        .unwrap();
}
