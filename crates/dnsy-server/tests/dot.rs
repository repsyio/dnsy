//! `DoT` listener tests. All sockets bind port 0; certificates come from a throwaway test CA.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use dnsy_engine::{Handler, RequestContext};
use dnsy_proto::{Class, Edns, EdnsOption, Message, Name, Question, Rcode, RecordType};
use dnsy_server::{DotConfig, Server, ServerConfig};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

struct Echo;

impl Handler for Echo {
    async fn handle(&self, ctx: RequestContext, query: Message) -> Message {
        let mut r = Message::response_to(&query);
        // Lets tests see which transport the engine was told about.
        r.header.rcode = if ctx.transport == dnsy_core::Transport::Dot {
            Rcode::NoError
        } else {
            Rcode::ServFail
        };
        r
    }
}

struct Pki {
    ca_der: CertificateDer<'static>,
    ca: Issuer<'static, KeyPair>,
}

fn pki() -> Pki {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_der = params.self_signed(&key).unwrap().der().clone();
    Pki {
        ca_der,
        ca: Issuer::new(params, key),
    }
}

/// Issues a leaf for `dns.test` and writes `cert.pem`/`key.pem` into `dir`; returns its DER.
fn issue(pki: &Pki, dir: &Path) -> Vec<u8> {
    let key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["dns.test".to_owned()])
        .unwrap()
        .signed_by(&key, &pki.ca)
        .unwrap();
    std::fs::write(dir.join("cert.pem"), leaf.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), key.serialize_pem()).unwrap();
    leaf.der().to_vec()
}

async fn start(dir: &Path, idle_ms: u64) -> (Server, SocketAddr) {
    let lo: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut config = ServerConfig::new(vec![], vec![]);
    config.dot = Some(DotConfig::new(
        vec![lo],
        dir.join("cert.pem"),
        dir.join("key.pem"),
    ));
    config.tcp_idle = Duration::from_millis(idle_ms);
    let server = Server::start(config, Arc::new(Echo)).await.unwrap();
    let addr = server.dot_addrs()[0];
    (server, addr)
}

async fn connect(pki: &Pki, addr: SocketAddr) -> std::io::Result<TlsStream<TcpStream>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pki.ca_der.clone()).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"dot".to_vec()];
    let tcp = TcpStream::connect(addr).await?;
    TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("dns.test").unwrap(), tcp)
        .await
}

fn query(id: u16, padding: bool) -> Message {
    let mut m = Message::response_to(&Message::decode(&[0; 12]).unwrap());
    m.header.qr = false;
    m.header.rd = true;
    m.header.id = id;
    m.questions.push(Question {
        name: Name::from_ascii("example.com.").unwrap(),
        qtype: RecordType::A,
        qclass: Class::In,
    });
    m.edns = Some(Edns {
        options: if padding {
            vec![EdnsOption::Padding(0)]
        } else {
            vec![]
        },
        ..Edns::default()
    });
    m
}

async fn ask(tls: &mut TlsStream<TcpStream>, q: &Message) -> Vec<u8> {
    let bytes = q.encode(65535).unwrap();
    tls.write_all(&(u16::try_from(bytes.len()).unwrap()).to_be_bytes())
        .await
        .unwrap();
    tls.write_all(&bytes).await.unwrap();
    let mut len = [0; 2];
    tls.read_exact(&mut len).await.unwrap();
    let mut buf = vec![0; usize::from(u16::from_be_bytes(len))];
    tls.read_exact(&mut buf).await.unwrap();
    buf
}

fn peer_leaf(tls: &TlsStream<TcpStream>) -> Vec<u8> {
    tls.get_ref().1.peer_certificates().unwrap()[0].to_vec()
}

/// Polls until a fresh connection is served `want`, or fails after a few seconds.
async fn wait_for_leaf(pki: &Pki, addr: SocketAddr, want: &[u8]) {
    for _ in 0..100 {
        if let Ok(tls) = connect(pki, addr).await
            && peer_leaf(&tls) == want
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("certificate was not reloaded");
}

#[tokio::test]
async fn dot_query_with_test_ca() {
    let dir = tempfile::tempdir().unwrap();
    let pki = pki();
    issue(&pki, dir.path());
    let (server, addr) = start(dir.path(), 5000).await;

    let mut tls = connect(&pki, addr).await.unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"dot"[..]));
    let version = tls.get_ref().1.protocol_version().unwrap();
    assert_eq!(version, rustls::ProtocolVersion::TLSv1_3);

    // Two queries on one connection; the handler saw transport Dot (NoError, not ServFail).
    for id in [7, 8] {
        let reply = Message::decode(&ask(&mut tls, &query(id, false)).await).unwrap();
        assert_eq!(reply.header.id, id);
        assert_eq!(reply.header.rcode, Rcode::NoError);
    }
    server.shutdown().await;
}

#[tokio::test]
async fn dot_pads_responses_when_requested() {
    let dir = tempfile::tempdir().unwrap();
    let pki = pki();
    issue(&pki, dir.path());
    let (server, addr) = start(dir.path(), 5000).await;
    let mut tls = connect(&pki, addr).await.unwrap();

    let padded = ask(&mut tls, &query(1, true)).await;
    assert_eq!(padded.len() % 468, 0, "len {}", padded.len());
    let plain = ask(&mut tls, &query(2, false)).await;
    assert_ne!(plain.len() % 468, 0);
    server.shutdown().await;
}

#[tokio::test]
async fn cert_reload_serves_new_cert() {
    let dir = tempfile::tempdir().unwrap();
    let pki = pki();
    let first = issue(&pki, dir.path());
    let (server, addr) = start(dir.path(), 5000).await;

    let mut open = connect(&pki, addr).await.unwrap();
    assert_eq!(peer_leaf(&open), first);

    // A broken rewrite is ignored: the old certificate keeps being served.
    std::fs::write(dir.path().join("cert.pem"), "garbage").unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(peer_leaf(&connect(&pki, addr).await.unwrap()), first);

    let second = issue(&pki, dir.path());
    assert_ne!(first, second);
    wait_for_leaf(&pki, addr, &second).await;

    // The connection opened before the reload was not dropped.
    let reply = Message::decode(&ask(&mut open, &query(3, false)).await).unwrap();
    assert_eq!(reply.header.id, 3);
    server.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn sighup_reloads_cert() {
    let dir = tempfile::tempdir().unwrap();
    let pki = pki();
    let first = issue(&pki, dir.path());
    let (server, addr) = start(dir.path(), 5000).await;
    assert_eq!(peer_leaf(&connect(&pki, addr).await.unwrap()), first);

    let second = issue(&pki, dir.path());
    let status = std::process::Command::new("kill")
        .args(["-HUP", &std::process::id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    wait_for_leaf(&pki, addr, &second).await;
    server.shutdown().await;
}

#[tokio::test]
async fn plain_tcp_on_dot_port_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let pki = pki();
    issue(&pki, dir.path());
    let (server, addr) = start(dir.path(), 5000).await;

    let mut tcp = TcpStream::connect(addr).await.unwrap();
    let bytes = query(1, false).encode(512).unwrap();
    let _ = tcp
        .write_all(&(u16::try_from(bytes.len()).unwrap()).to_be_bytes())
        .await;
    let _ = tcp.write_all(&bytes).await;
    // The server answers with a TLS alert at most, never a DNS response, then closes.
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), tcp.read_to_end(&mut got))
        .await
        .expect("connection closed");
    assert!(got.is_empty() || got[0] == 0x15, "unexpected reply {got:?}");
    server.shutdown().await;
}

#[tokio::test]
async fn dot_idle_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let pki = pki();
    issue(&pki, dir.path());
    let (server, addr) = start(dir.path(), 300).await;
    let mut tls = connect(&pki, addr).await.unwrap();

    let mut buf = [0; 16];
    let n = tokio::time::timeout(Duration::from_secs(3), tls.read(&mut buf))
        .await
        .expect("server closed the idle connection");
    assert!(matches!(n, Ok(0) | Err(_)));
    server.shutdown().await;
}

#[tokio::test]
async fn missing_key_fails_start() {
    let dir = tempfile::tempdir().unwrap();
    let lo: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut config = ServerConfig::new(vec![], vec![]);
    config.dot = Some(DotConfig::new(
        vec![lo],
        dir.path().join("cert.pem"),
        dir.path().join("key.pem"),
    ));
    assert!(Server::start(config, Arc::new(Echo)).await.is_err());
}
