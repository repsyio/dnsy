use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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
    TestPki {
        ca_der: ca.der().clone(),
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
