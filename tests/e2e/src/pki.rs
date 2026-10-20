//! Throwaway certificate authorities, a server certificate and client certificates.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType, date_time_ymd,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::{Digest, Sha256};

struct Ca {
    der: CertificateDer<'static>,
    pem: String,
    issuer: Issuer<'static, KeyPair>,
}

fn ca(name: &str) -> Ca {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let cert = params.self_signed(&key).expect("ca cert");
    Ca {
        der: cert.der().clone(),
        pem: cert.pem(),
        issuer: Issuer::new(params, key),
    }
}

/// A client certificate and its private key (DER).
#[derive(Clone)]
pub struct ClientIdentity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

impl ClientIdentity {
    /// SHA-256 of the certificate, lowercase hex (the form the API takes).
    pub fn fingerprint(&self) -> String {
        crate::hex(&Sha256::digest(&self.cert_der))
    }
}

fn client(ca: &Ca, cn: &str, expired: bool) -> ClientIdentity {
    let key = KeyPair::generate().expect("client key");
    let mut params = CertificateParams::new(vec![format!("{cn}.client.test")]).expect("params");
    params.distinguished_name.push(DnType::CommonName, cn);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    if expired {
        params.not_before = date_time_ymd(2000, 1, 1);
        params.not_after = date_time_ymd(2001, 1, 1);
    }
    let cert = params.signed_by(&key, &ca.issuer).expect("client cert");
    ClientIdentity {
        cert_der: cert.der().to_vec(),
        key_der: key.serialize_der(),
    }
}

/// The server CA, the client CA and the certificates issued by them.
pub struct Pki {
    /// The CA that issued the server certificate (PEM), for external clients (`kdig +tls-ca`).
    pub server_ca_pem: String,
    server_ca_der: CertificateDer<'static>,
    /// Client CA bundle the server trusts (PEM).
    pub client_ca_pem: String,
    /// The CA behind `untrusted_client` (PEM); append it to the client CA bundle to trust it.
    pub untrusted_ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    /// Issued by the trusted client CA.
    pub valid_client: ClientIdentity,
    /// Issued by the trusted client CA but already expired.
    pub expired_client: ClientIdentity,
    /// Issued by a CA the server does not trust.
    pub untrusted_client: ClientIdentity,
}

impl Pki {
    pub fn generate() -> Pki {
        let server_ca = ca("e2e server ca");
        let client_ca = ca("e2e client ca");
        let other_ca = ca("e2e untrusted ca");
        let key = KeyPair::generate().expect("server key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.subject_alt_names = vec![
            SanType::DnsName("localhost".try_into().expect("dns name")),
            SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = params
            .signed_by(&key, &server_ca.issuer)
            .expect("server cert");
        Pki {
            server_ca_pem: server_ca.pem.clone(),
            server_ca_der: server_ca.der.clone(),
            client_ca_pem: client_ca.pem.clone(),
            untrusted_ca_pem: other_ca.pem.clone(),
            server_cert_pem: leaf.pem(),
            server_key_pem: key.serialize_pem(),
            valid_client: client(&client_ca, "alice", false),
            expired_client: client(&client_ca, "old", true),
            untrusted_client: client(&other_ca, "mallory", false),
        }
    }

    /// Writes `server.pem`, `server.key`, `client-ca.pem` and `ca.pem` into `dir`.
    pub fn write(&self, dir: &Path) {
        for (name, text) in [
            ("server.pem", &self.server_cert_pem),
            ("server.key", &self.server_key_pem),
            ("client-ca.pem", &self.client_ca_pem),
            ("ca.pem", &self.server_ca_pem),
        ] {
            std::fs::write(dir.join(name), text).expect("write pki file");
        }
    }

    /// A TLS client configuration trusting the server CA, with an optional client certificate.
    pub fn client_config(
        &self,
        identity: Option<&ClientIdentity>,
        alpn: &[&[u8]],
    ) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.server_ca_der.clone()).expect("root");
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots);
        let mut config = match identity {
            Some(c) => builder
                .with_client_auth_cert(
                    vec![CertificateDer::from(c.cert_der.clone())],
                    PrivateKeyDer::try_from(c.key_der.clone()).expect("key"),
                )
                .expect("client auth"),
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Arc::new(config)
    }

    /// The name the server certificate is valid for.
    pub fn server_name() -> ServerName<'static> {
        ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into())
    }
}

/// Installs the ring crypto provider as the process default (reqwest needs one); idempotent.
pub fn install_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
