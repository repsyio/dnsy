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
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Bumped on every replacement so open connections know to re-check their certificate.
    generation: Arc<AtomicU64>,
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
        self.generation.fetch_add(1, Ordering::Release);
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
    /// Bumped when the CA bundle or CRL is reloaded.
    generation: AtomicU64,
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
            generation: AtomicU64::new(0),
        }))
    }

    /// Re-reads the CA bundle and CRL file. On failure the previous state stays in effect.
    ///
    /// # Errors
    /// Unreadable CA bundle or CRL file.
    pub fn reload(&self) -> io::Result<()> {
        self.inner
            .store(Arc::new(build(self.mode, &self.ca, self.crl.as_deref())?));
        self.generation.fetch_add(1, Ordering::Release);
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

    /// Changes whenever the CA, CRL or allowlist changed; open connections re-check on a change.
    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
            + self
                .allowlist
                .as_ref()
                .map_or(0, |a| a.generation.load(Ordering::Acquire))
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
    let (cn, sans) = subject_parts(der).unwrap_or_default();
    let mut parts = Vec::new();
    if let Some(cn) = cn {
        parts.push(format!("CN={cn}"));
    }
    if !sans.is_empty() {
        parts.push(format!("SAN={}", sans.join(",")));
    }
    // Subject text comes from the client certificate; keep it log-safe and bounded.
    parts
        .join(" ")
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .take(256)
        .collect()
}

const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_OID: u8 = 0x06;
const TAG_OCTET_STRING: u8 = 0x04;
/// `[0]` explicit, constructed: the optional `TBSCertificate` version.
const TAG_VERSION: u8 = 0xa0;
/// `[3]` explicit, constructed: the `TBSCertificate` extensions.
const TAG_EXTENSIONS: u8 = 0xa3;
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
/// String types a common name can use (UTF8, Printable, T61, IA5, BMP is skipped).
const CN_STRING_TAGS: &[u8] = &[0x0c, 0x13, 0x14, 0x16];
/// `GeneralName` context tags `[1]` rfc822Name, `[2]` dNSName, `[6]` uniformResourceIdentifier.
const SAN_TEXT_TAGS: &[u8] = &[0x81, 0x82, 0x86];

/// Reads one DER element and returns `(tag, content, rest)`. Definite lengths only.
fn der_element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let (len_bytes, rest) = rest.split_at(n);
        let len = len_bytes
            .iter()
            .fold(0_usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, rest)
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// Iterates the elements of a DER constructed value's content.
fn der_children(mut content: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    std::iter::from_fn(move || {
        let (tag, body, rest) = der_element(content)?;
        content = rest;
        Some((tag, body))
    })
}

/// Common name and text subject alternative names of an X.509 certificate, by walking the DER
/// (`Certificate`, `TBSCertificate`, subject and extensions). `None` when it is not parseable.
fn subject_parts(der: &[u8]) -> Option<(Option<String>, Vec<String>)> {
    let (tag, cert, _) = der_element(der)?;
    (tag == TAG_SEQUENCE).then_some(())?;
    let (tag, tbs, _) = der_element(cert)?;
    (tag == TAG_SEQUENCE).then_some(())?;
    let mut fields = der_children(tbs).peekable();
    if fields.peek().is_some_and(|(t, _)| *t == TAG_VERSION) {
        fields.next();
    }
    // serial, signature, issuer, validity, then subject.
    let subject = fields.nth(4).filter(|(t, _)| *t == TAG_SEQUENCE)?.1;
    let cn = der_children(subject)
        .filter(|(t, _)| *t == TAG_SET)
        .flat_map(|(_, rdn)| der_children(rdn).map(|(_, atv)| atv))
        .find_map(|atv| {
            let mut it = der_children(atv);
            let (oid_tag, oid) = it.next()?;
            let (value_tag, value) = it.next()?;
            (oid_tag == TAG_OID && oid == OID_COMMON_NAME && CN_STRING_TAGS.contains(&value_tag))
                .then(|| std::str::from_utf8(value).ok().map(str::to_owned))?
        });
    // spki, then optional issuerUID/subjectUID, then `[3]` extensions.
    let sans = fields
        .find(|(t, _)| *t == TAG_EXTENSIONS)
        .and_then(|(_, ext)| der_element(ext))
        .map(|(_, list, _)| {
            der_children(list)
                .filter_map(|(_, extn)| {
                    let mut it = der_children(extn);
                    let (oid_tag, oid) = it.next()?;
                    (oid_tag == TAG_OID && oid == OID_SUBJECT_ALT_NAME).then_some(())?;
                    // Skip the optional `critical` BOOLEAN.
                    let (_, value) = it.find(|(t, _)| *t == TAG_OCTET_STRING)?;
                    let (_, names, _) = der_element(value)?;
                    Some(
                        der_children(names)
                            .filter(|(t, _)| SAN_TEXT_TAGS.contains(t))
                            .filter_map(|(_, v)| std::str::from_utf8(v).ok().map(str::to_owned))
                            .collect::<Vec<_>>(),
                    )
                })
                .flatten()
                .collect()
        })
        .unwrap_or_default();
    Some((cn, sans))
}

/// An authenticated `DoT` connection: who it is and whether it is still allowed.
///
/// Created right after the handshake. Resumed sessions skip certificate verification, so
/// resumption is disabled when a verifier is set (see `dot::acceptor`); this re-check is the
/// second line of defence, and also catches revocation while a connection stays open.
pub(crate) struct ClientSession {
    pub(crate) principal: Principal,
    chain: Vec<CertificateDer<'static>>,
    verifier: Option<(Arc<MtlsVerifier>, u64)>,
}

impl ClientSession {
    /// `None` when the peer presented no certificate. `Err` when the certificate is no longer
    /// acceptable to `verifier`.
    pub(crate) fn new(
        chain: Option<&[CertificateDer<'static>]>,
        verifier: Option<&Arc<MtlsVerifier>>,
    ) -> Result<Option<Self>, ()> {
        let Some(chain) = chain.filter(|c| !c.is_empty()) else {
            return Ok(None);
        };
        let mut session = Self {
            principal: principal(&chain[0]),
            chain: chain.to_vec(),
            verifier: verifier.map(|v| (Arc::clone(v), v.generation().wrapping_sub(1))),
        };
        if session.still_permitted() {
            Ok(Some(session))
        } else {
            Err(())
        }
    }

    /// Re-verifies the chain against the current CA, CRL and allowlist when any of them
    /// changed since the last check.
    pub(crate) fn still_permitted(&mut self) -> bool {
        let Some((verifier, seen)) = &mut self.verifier else {
            return true;
        };
        let now = verifier.generation();
        if now == *seen {
            return true;
        }
        *seen = now;
        verifier
            .verify_client_cert(&self.chain[0], &self.chain[1..], UnixTime::now())
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    fn cert(cn: Option<&str>, sans: Vec<SanType>) -> Vec<u8> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = DistinguishedName::new();
        if let Some(cn) = cn {
            params.distinguished_name.push(DnType::CommonName, cn);
        }
        params.subject_alt_names = sans;
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn subject_has_common_name_and_text_sans() {
        let der = cert(
            Some("alice"),
            vec![
                SanType::DnsName("laptop.example".try_into().unwrap()),
                SanType::Rfc822Name("alice@example.com".try_into().unwrap()),
                SanType::URI("spiffe://example/alice".try_into().unwrap()),
                SanType::IpAddress([192, 0, 2, 1].into()),
            ],
        );
        assert_eq!(
            subject(&der),
            "CN=alice SAN=laptop.example,alice@example.com,spiffe://example/alice"
        );
    }

    #[test]
    fn subject_without_san_or_cn() {
        assert_eq!(subject(&cert(Some("bob"), vec![])), "CN=bob");
        assert_eq!(
            subject(&cert(
                None,
                vec![SanType::DnsName("only.example".try_into().unwrap())]
            )),
            "SAN=only.example"
        );
    }

    #[test]
    fn subject_of_garbage_is_empty() {
        assert_eq!(subject(&[]), "");
        assert_eq!(subject(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]), "");
        let mut der = cert(Some("alice"), vec![]);
        der.truncate(der.len() / 2);
        assert_eq!(subject(&der), "");
    }

    #[test]
    fn subject_is_log_safe_and_bounded() {
        let long = "a".repeat(400);
        assert_eq!(subject(&cert(Some(&long), vec![])).chars().count(), 256);
        assert_eq!(subject(&cert(Some("a\nb"), vec![])), "CN=a?b");
    }
}
