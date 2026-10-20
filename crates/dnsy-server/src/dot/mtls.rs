//! mTLS client authentication for `DoT`.
//!
//! [`MtlsVerifier`] wraps rustls' `WebPkiClientVerifier` (chain to the configured client CA,
//! validity period, optional CRL) and adds a fingerprint allowlist. After the handshake the
//! listener turns the verified leaf into a [`Principal::ClientCert`]; raw certificates are never
//! logged, only the SHA-256 fingerprint and a short subject string.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use dnsy_auth::ClientCertService;
use dnsy_core::Principal;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::ring::default_provider;
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer, UnixTime};
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

/// Client certificate policy once mTLS is on (`off` means no verifier at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtlsMode {
    /// Clients may connect without a certificate; a presented one must be valid.
    Optional,
    /// Connections without a valid certificate are refused during the handshake.
    Required,
}

/// Allowed certificate in the in-memory allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowedCert {
    pub sha256: [u8; 32],
    /// Unix seconds; `None` never expires.
    pub expires_at: Option<i64>,
}

/// Shared, hot-swappable fingerprint allowlist. Once attached to a verifier, a presented
/// certificate must be on it (an empty list admits no certificate).
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    entries: Arc<ArcSwap<HashMap<[u8; 32], Option<i64>>>>,
}

impl Allowlist {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the whole list.
    pub fn replace(&self, certs: impl IntoIterator<Item = AllowedCert>) {
        let map = certs
            .into_iter()
            .map(|c| (c.sha256, c.expires_at))
            .collect();
        self.entries.store(Arc::new(map));
    }

    /// Reloads the enabled, unexpired entries from the database.
    ///
    /// # Errors
    /// Store failure; the previous list stays in effect.
    pub async fn refresh(&self, service: &ClientCertService) -> Result<(), dnsy_store::StoreError> {
        let active = service.active().await?;
        self.replace(active.into_iter().map(|c| AllowedCert {
            sha256: c.sha256,
            expires_at: c.expires_at,
        }));
        Ok(())
    }

    /// Reloads from the database every `every`, keeping the old list on failure.
    #[must_use]
    pub fn spawn_refresh(&self, service: ClientCertService, every: Duration) -> JoinHandle<()> {
        let list = self.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = list.refresh(&service).await {
                    tracing::warn!(error = %e, "client certificate allowlist refresh failed");
                }
                tokio::time::sleep(every).await;
            }
        })
    }

    fn permits(&self, sha256: &[u8; 32], now: i64) -> bool {
        self.entries
            .load()
            .get(sha256)
            .is_some_and(|exp| exp.is_none_or(|t| t > now))
    }
}

/// Client certificate verifier: client CA chain validation, optional CRL, optional allowlist.
pub struct MtlsVerifier {
    mode: MtlsMode,
    ca: PathBuf,
    crl: Option<PathBuf>,
    allowlist: Option<Allowlist>,
    inner: ArcSwap<Arc<dyn ClientCertVerifier>>,
}

impl std::fmt::Debug for MtlsVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MtlsVerifier")
            .field("mode", &self.mode)
            .field("ca", &self.ca)
            .field("crl", &self.crl)
            .field("allowlist", &self.allowlist.is_some())
            .finish_non_exhaustive()
    }
}

impl MtlsVerifier {
    /// Builds the verifier from the client CA bundle (PEM). `crl` is a PEM file of CRLs and
    /// `allowlist`, when set, restricts connections to listed fingerprints.
    ///
    /// # Errors
    /// Unreadable or empty CA bundle, or unreadable CRL file.
    pub fn new(
        mode: MtlsMode,
        ca: &Path,
        crl: Option<&Path>,
        allowlist: Option<Allowlist>,
    ) -> io::Result<Arc<Self>> {
        let inner = build(mode, ca, crl)?;
        Ok(Arc::new(Self {
            mode,
            ca: ca.to_owned(),
            crl: crl.map(Path::to_owned),
            allowlist,
            inner: ArcSwap::from_pointee(inner),
        }))
    }

    /// Re-reads the CA bundle and CRL file. On failure the previous state stays in effect.
    ///
    /// # Errors
    /// Unreadable CA bundle or CRL file.
    pub fn reload(&self) -> io::Result<()> {
        self.inner
            .store(Arc::new(build(self.mode, &self.ca, self.crl.as_deref())?));
        Ok(())
    }

    /// Calls [`Self::reload`] every `every`; failures are logged and the old state is kept.
    #[must_use]
    pub fn spawn_reload(self: &Arc<Self>, every: Duration) -> JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                if let Err(e) = this.reload() {
                    tracing::warn!(error = %e, "client CA/CRL reload failed; keeping previous");
                }
            }
        })
    }

    #[must_use]
    pub fn as_verifier(self: &Arc<Self>) -> Arc<dyn ClientCertVerifier> {
        Arc::clone(self) as Arc<dyn ClientCertVerifier>
    }

    fn inner(&self) -> Arc<dyn ClientCertVerifier> {
        Arc::clone(&self.inner.load())
    }
}

fn build(mode: MtlsMode, ca: &Path, crl: Option<&Path>) -> io::Result<Arc<dyn ClientCertVerifier>> {
    let mut roots = rustls::RootCertStore::empty();
    for der in CertificateDer::pem_file_iter(ca).map_err(io::Error::other)? {
        roots
            .add(der.map_err(io::Error::other)?)
            .map_err(io::Error::other)?;
    }
    if roots.is_empty() {
        return Err(io::Error::other("client CA bundle contains no certificate"));
    }
    let mut builder =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::new(default_provider()));
    if let Some(crl) = crl {
        let crls = CertificateRevocationListDer::pem_file_iter(crl)
            .map_err(io::Error::other)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(io::Error::other)?;
        if crls.is_empty() {
            return Err(io::Error::other("CRL file contains no CRL"));
        }
        builder = builder.with_crls(crls);
    }
    if mode == MtlsMode::Optional {
        builder = builder.allow_unauthenticated();
    }
    builder.build().map_err(io::Error::other)
}

impl ClientCertVerifier for MtlsVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner().offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner().client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // Hints are optional (RFC 8446 section 4.2.4); an empty list avoids borrowing from
        // the swappable inner verifier.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let verified = self
            .inner()
            .verify_client_cert(end_entity, intermediates, now)?;
        if let Some(list) = &self.allowlist {
            let sha256: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
            let now = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
            if !list.permits(&sha256, now) {
                return Err(rustls::Error::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ));
            }
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner().verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner().verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner().supported_verify_schemes()
    }
}

/// Identity of a verified client leaf certificate: SHA-256 of the DER plus `CN=...`/`SAN=...`.
#[must_use]
pub(crate) fn principal(der: &[u8]) -> Principal {
    Principal::ClientCert {
        sha256: Sha256::digest(der).into(),
        subject: subject(der),
    }
}

fn subject(der: &[u8]) -> String {
    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return String::new();
    };
    let mut parts = Vec::new();
    if let Some(cn) = cert
        .subject()
        .iter_common_name()
        .find_map(|a| a.as_str().ok())
    {
        parts.push(format!("CN={cn}"));
    }
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        let names: Vec<&str> = san
            .value
            .general_names
            .iter()
            .filter_map(|n| match n {
                GeneralName::DNSName(s) | GeneralName::RFC822Name(s) | GeneralName::URI(s) => {
                    Some(*s)
                }
                _ => None,
            })
            .collect();
        if !names.is_empty() {
            parts.push(format!("SAN={}", names.join(",")));
        }
    }
    // Subject text comes from the client certificate; keep it log-safe and bounded.
    parts
        .join(" ")
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .take(256)
        .collect()
}
