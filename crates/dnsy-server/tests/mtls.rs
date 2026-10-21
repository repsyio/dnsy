//! mTLS tests for `DoT`: generated CAs, client certificates and CRLs; port 0 only.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dnsy_auth::ClientCertService;
use dnsy_core::Principal;
use dnsy_engine::{Handler, RequestContext};
use dnsy_proto::{Class, Message, Name, Question, RecordType};
use dnsy_server::{
    AllowedCert, Allowlist, DotConfig, MtlsMode, MtlsVerifier, Server, ServerConfig,
};
use dnsy_store::Store;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, IsCa, Issuer,
    KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
    date_time_ymd,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Records the principal of every request.
#[derive(Default)]
struct Recorder(Mutex<Vec<Option<Principal>>>);

struct Shared(Arc<Recorder>);

impl Handler for Shared {
    fn handle(&self, ctx: RequestContext, query: Message) -> impl Future<Output = Message> + Send {
        self.0.0.lock().unwrap().push(ctx.principal);
        std::future::ready(Message::response_to(&query))
    }
}

struct Ca {
    der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
    pem: String,
}

fn ca() -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let cert = params.self_signed(&key).unwrap();
    Ca {
        der: cert.der().clone(),
        pem: cert.pem(),
        issuer: Issuer::new(params, key),
    }
}

struct Client {
    der: Vec<u8>,
    key: Vec<u8>,
}

fn client(ca: &Ca, serial: u64, expired: bool) -> Client {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["laptop.example".to_owned()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "alice");
    params.serial_number = Some(SerialNumber::from(serial));
    if expired {
        params.not_before = date_time_ymd(2000, 1, 1);
        params.not_after = date_time_ymd(2001, 1, 1);
    }
    let cert = params.signed_by(&key, &ca.issuer).unwrap();
    Client {
        der: cert.der().to_vec(),
        key: key.serialize_der(),
    }
}

fn crl_pem(ca: &Ca, revoked: &[u64]) -> String {
    let now = date_time_ymd(2026, 1, 1);
    CertificateRevocationListParams {
        this_update: date_time_ymd(2020, 1, 1),
        next_update: date_time_ymd(2200, 1, 1),
        crl_number: SerialNumber::from(1_u64),
        issuing_distribution_point: None,
        revoked_certs: revoked
            .iter()
            .map(|s| RevokedCertParams {
                serial_number: SerialNumber::from(*s),
                revocation_time: now,
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            })
            .collect(),
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&ca.issuer)
    .unwrap()
    .pem()
    .unwrap()
}

fn fingerprint(c: &Client) -> [u8; 32] {
    Sha256::digest(&c.der).into()
}

struct Env {
    dir: tempfile::TempDir,
    server_ca: Ca,
    client_ca: Ca,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let server_ca = ca();
    let client_ca = ca();
    let key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["dns.test".to_owned()])
        .unwrap()
        .signed_by(&key, &server_ca.issuer)
        .unwrap();
    std::fs::write(dir.path().join("cert.pem"), leaf.pem()).unwrap();
    std::fs::write(dir.path().join("key.pem"), key.serialize_pem()).unwrap();
    std::fs::write(dir.path().join("client-ca.pem"), &client_ca.pem).unwrap();
    Env {
        dir,
        server_ca,
        client_ca,
    }
}

async fn start(env: &Env, verifier: &Arc<MtlsVerifier>) -> (Server, SocketAddr, Arc<Recorder>) {
    let lo: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let dot = DotConfig::new(
        vec![lo],
        env.dir.path().join("cert.pem"),
        env.dir.path().join("key.pem"),
    )
    .with_mtls(Arc::clone(verifier));
    let mut config = ServerConfig::new(vec![], vec![]);
    config.dot = Some(dot);
    let rec = Arc::new(Recorder::default());
    let server = Server::start(config, Arc::new(Shared(Arc::clone(&rec))))
        .await
        .unwrap();
    let addr = server.dot_addrs()[0];
    (server, addr, rec)
}

fn verifier(env: &Env, mode: MtlsMode, allow: Option<Allowlist>) -> Arc<MtlsVerifier> {
    MtlsVerifier::new(mode, &env.dir.path().join("client-ca.pem"), None, allow).unwrap()
}

fn client_config(env: &Env, client: Option<&Client>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(env.server_ca.der.clone()).unwrap();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots);
    let mut config = match client {
        Some(c) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from(c.der.clone())],
                PrivateKeyDer::try_from(c.key.clone()).unwrap(),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"dot".to_vec()];
    Arc::new(config)
}

async fn connect(
    addr: SocketAddr,
    config: &Arc<rustls::ClientConfig>,
) -> std::io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    TlsConnector::from(Arc::clone(config))
        .connect(ServerName::try_from("dns.test").unwrap(), tcp)
        .await
}

/// Sends one query and waits for the reply; `Err` if the server refused or closed.
async fn ask(tls: &mut TlsStream<TcpStream>) -> std::io::Result<()> {
    let mut q = Message::response_to(&Message::decode(&[0; 12]).unwrap());
    q.header.qr = false;
    q.header.rd = true;
    q.header.id = 9;
    q.questions.push(Question {
        name: Name::from_ascii("example.com.").unwrap(),
        qtype: RecordType::A,
        qclass: Class::In,
    });
    let bytes = q.encode(65535).unwrap();
    tls.write_all(&(u16::try_from(bytes.len()).unwrap()).to_be_bytes())
        .await?;
    tls.write_all(&bytes).await?;
    let mut len = [0; 2];
    tokio::time::timeout(Duration::from_secs(5), tls.read_exact(&mut len))
        .await
        .map_err(std::io::Error::other)??;
    let mut buf = vec![0; usize::from(u16::from_be_bytes(len))];
    tls.read_exact(&mut buf).await?;
    Ok(())
}

/// Connects (optionally with a client certificate) and runs one query; `Err` means the
/// handshake or the exchange was refused.
async fn query(env: &Env, addr: SocketAddr, client: Option<&Client>) -> std::io::Result<()> {
    let mut tls = connect(addr, &client_config(env, client)).await?;
    ask(&mut tls).await
}

fn allow(certs: &[&Client]) -> Allowlist {
    let list = Allowlist::new();
    list.replace(certs.iter().map(|c| AllowedCert {
        sha256: fingerprint(c),
        expires_at: None,
    }));
    list
}

#[tokio::test]
async fn required_rejects_no_cert() {
    let env = env();
    let v = verifier(&env, MtlsMode::Required, None);
    let (server, addr, rec) = start(&env, &v).await;
    assert!(query(&env, addr, None).await.is_err());
    assert!(rec.0.lock().unwrap().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn required_accepts_valid_cert() {
    let env = env();
    let v = verifier(&env, MtlsMode::Required, None);
    let (server, addr, _rec) = start(&env, &v).await;
    let c = client(&env.client_ca, 1, false);
    query(&env, addr, Some(&c)).await.unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn optional_allows_anonymous_but_not_invalid() {
    let env = env();
    let v = verifier(&env, MtlsMode::Optional, None);
    let (server, addr, rec) = start(&env, &v).await;
    query(&env, addr, None).await.unwrap();
    assert_eq!(rec.0.lock().unwrap().as_slice(), &[None]);
    let other = ca();
    assert!(
        query(&env, addr, Some(&client(&other, 2, false)))
            .await
            .is_err()
    );
    server.shutdown().await;
}

#[tokio::test]
async fn wrong_ca_rejected() {
    let env = env();
    let v = verifier(&env, MtlsMode::Required, None);
    let (server, addr, _rec) = start(&env, &v).await;
    let c = client(&ca(), 1, false);
    assert!(query(&env, addr, Some(&c)).await.is_err());
    server.shutdown().await;
}

#[tokio::test]
async fn expired_cert_rejected() {
    let env = env();
    let v = verifier(&env, MtlsMode::Required, None);
    let (server, addr, _rec) = start(&env, &v).await;
    let c = client(&env.client_ca, 1, true);
    assert!(query(&env, addr, Some(&c)).await.is_err());
    server.shutdown().await;
}

#[tokio::test]
async fn revoked_cert_rejected_and_crl_reload() {
    let env = env();
    let crl = env.dir.path().join("crl.pem");
    std::fs::write(&crl, crl_pem(&env.client_ca, &[])).unwrap();
    let v = MtlsVerifier::new(
        MtlsMode::Required,
        &env.dir.path().join("client-ca.pem"),
        Some(&crl),
        None,
    )
    .unwrap();
    let (server, addr, _rec) = start(&env, &v).await;
    let good = client(&env.client_ca, 10, false);
    let bad = client(&env.client_ca, 11, false);
    query(&env, addr, Some(&good)).await.unwrap();
    query(&env, addr, Some(&bad)).await.unwrap();

    // A broken CRL file keeps the previous state.
    std::fs::write(&crl, "garbage").unwrap();
    assert!(v.reload().is_err());
    std::fs::write(&crl, crl_pem(&env.client_ca, &[11])).unwrap();
    v.reload().unwrap();
    assert!(query(&env, addr, Some(&bad)).await.is_err());
    query(&env, addr, Some(&good)).await.unwrap();
    server.shutdown().await;
}

#[tokio::test]
async fn fingerprint_allowlist_enforced() {
    let env = env();
    let listed = client(&env.client_ca, 1, false);
    let unlisted = client(&env.client_ca, 2, false);
    let list = allow(&[&listed]);
    let v = verifier(&env, MtlsMode::Required, Some(list.clone()));
    let (server, addr, _rec) = start(&env, &v).await;
    query(&env, addr, Some(&listed)).await.unwrap();
    assert!(query(&env, addr, Some(&unlisted)).await.is_err());

    list.replace([]);
    assert!(query(&env, addr, Some(&listed)).await.is_err());
    server.shutdown().await;
}

#[tokio::test]
async fn allowlist_from_database_honours_enabled_and_expiry() {
    let env = env();
    let store = Store::open(&env.dir.path().join("t.db")).unwrap();
    let svc = ClientCertService::new(store);
    let a = client(&env.client_ca, 1, false);
    let b = client(&env.client_ca, 2, false);
    let c = client(&env.client_ca, 3, false);
    let ea = svc.add(fingerprint(&a), "a", None).await.unwrap();
    svc.add(fingerprint(&b), "b", Some(1)).await.unwrap(); // expired long ago
    svc.add(fingerprint(&c), "c", None).await.unwrap();
    svc.set_enabled(svc.list().await.unwrap()[2].id, false)
        .await
        .unwrap();

    let list = Allowlist::new();
    list.refresh(&svc).await.unwrap();
    let v = verifier(&env, MtlsMode::Required, Some(list.clone()));
    let (server, addr, _rec) = start(&env, &v).await;
    query(&env, addr, Some(&a)).await.unwrap();
    assert!(query(&env, addr, Some(&b)).await.is_err());
    assert!(query(&env, addr, Some(&c)).await.is_err());

    svc.remove(ea.id).await.unwrap();
    list.refresh(&svc).await.unwrap();
    assert!(query(&env, addr, Some(&a)).await.is_err());
    server.shutdown().await;
}

#[tokio::test]
async fn principal_in_query_event() {
    let env = env();
    let v = verifier(&env, MtlsMode::Required, None);
    let (server, addr, rec) = start(&env, &v).await;
    let c = client(&env.client_ca, 1, false);
    query(&env, addr, Some(&c)).await.unwrap();
    let seen = rec.0.lock().unwrap().clone();
    let [Some(Principal::ClientCert { sha256, subject })] = seen.as_slice() else {
        panic!("expected one client cert principal, got {seen:?}");
    };
    assert_eq!(*sha256, fingerprint(&c));
    assert_eq!(subject, "CN=alice SAN=laptop.example");
    server.shutdown().await;
}

#[test]
fn new_rejects_missing_or_empty_ca() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        MtlsVerifier::new(MtlsMode::Required, &dir.path().join("nope.pem"), None, None).is_err()
    );
    let empty: &Path = &dir.path().join("empty.pem");
    std::fs::write(empty, "").unwrap();
    assert!(MtlsVerifier::new(MtlsMode::Required, empty, None, None).is_err());
}

#[tokio::test]
async fn removed_cert_cannot_resume_session() {
    let env = env();
    let c = client(&env.client_ca, 1, false);
    let list = allow(&[&c]);
    let v = verifier(&env, MtlsMode::Required, Some(list.clone()));
    let (server, addr, _rec) = start(&env, &v).await;

    // One client config keeps its session cache, so the second connect tries to resume.
    let config = client_config(&env, Some(&c));
    let mut first = connect(addr, &config).await.unwrap();
    ask(&mut first).await.unwrap();
    drop(first);

    list.replace([]);
    let second = async {
        let mut tls = connect(addr, &config).await?;
        ask(&mut tls).await
    }
    .await;
    assert!(second.is_err());
    server.shutdown().await;
}

#[tokio::test]
async fn open_connection_closed_after_allowlist_removal() {
    let env = env();
    let c = client(&env.client_ca, 1, false);
    let list = allow(&[&c]);
    let v = verifier(&env, MtlsMode::Required, Some(list.clone()));
    let (server, addr, rec) = start(&env, &v).await;

    let mut tls = connect(addr, &client_config(&env, Some(&c))).await.unwrap();
    ask(&mut tls).await.unwrap();
    ask(&mut tls).await.unwrap();

    list.replace([]);
    assert!(ask(&mut tls).await.is_err());
    assert_eq!(rec.0.lock().unwrap().len(), 2);
    server.shutdown().await;
}

#[tokio::test]
async fn open_connection_closed_after_crl_reload() {
    let env = env();
    let crl = env.dir.path().join("crl.pem");
    std::fs::write(&crl, crl_pem(&env.client_ca, &[])).unwrap();
    let v = MtlsVerifier::new(
        MtlsMode::Required,
        &env.dir.path().join("client-ca.pem"),
        Some(&crl),
        None,
    )
    .unwrap();
    let (server, addr, _rec) = start(&env, &v).await;
    let c = client(&env.client_ca, 5, false);
    let mut tls = connect(addr, &client_config(&env, Some(&c))).await.unwrap();
    ask(&mut tls).await.unwrap();

    std::fs::write(&crl, crl_pem(&env.client_ca, &[5])).unwrap();
    v.reload().unwrap();
    assert!(ask(&mut tls).await.is_err());
    server.shutdown().await;
}
