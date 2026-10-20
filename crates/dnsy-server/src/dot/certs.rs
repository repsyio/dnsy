//! Certificate store with hot reload.
//!
//! The store is a rustls [`ResolvesServerCert`]: every new handshake reads the current key from
//! an [`ArcSwap`], so replacing it never touches established connections. A failed reload keeps
//! the previous certificate. Key material is never logged.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::{RecursiveMode, Watcher};
use rustls::crypto::ring::default_provider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::{mpsc, watch};

/// Quiet period after a file event before reloading (editors and renames emit bursts).
const DEBOUNCE: Duration = Duration::from_millis(150);

#[derive(Debug)]
pub(crate) struct CertStore {
    cert: PathBuf,
    key: PathBuf,
    current: ArcSwap<CertifiedKey>,
}

impl CertStore {
    /// Loads the certificate chain and key once.
    pub(crate) fn load(cert: &Path, key: &Path) -> io::Result<Arc<CertStore>> {
        let current = read(cert, key)?;
        Ok(Arc::new(CertStore {
            cert: cert.to_owned(),
            key: key.to_owned(),
            current: ArcSwap::from_pointee(current),
        }))
    }

    /// Re-reads both files; on failure the previous certificate stays in use.
    pub(crate) fn reload(&self) {
        match read(&self.cert, &self.key) {
            Ok(next) => {
                self.current.store(Arc::new(next));
                tracing::info!("tls certificate reloaded");
            }
            Err(e) => tracing::warn!(error = %e, "tls certificate reload failed; keeping previous"),
        }
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.load_full())
    }
}

fn read(cert: &Path, key: &Path) -> io::Result<CertifiedKey> {
    let chain = CertificateDer::pem_file_iter(cert)
        .map_err(io::Error::other)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    if chain.is_empty() {
        return Err(io::Error::other(format!(
            "no certificate in {}",
            cert.display()
        )));
    }
    let key = PrivateKeyDer::from_pem_file(key).map_err(io::Error::other)?;
    let signer = default_provider()
        .key_provider
        .load_private_key(key)
        .map_err(io::Error::other)?;
    let certified = CertifiedKey::new(chain, signer);
    // Rejects a key that does not belong to the certificate (e.g. mid-rotation).
    certified.keys_match().map_err(io::Error::other)?;
    Ok(certified)
}

/// Reloads `store` when the certificate or key changes on disk or on SIGHUP, until shutdown.
///
/// The parent directories are watched (not the files) so atomic renames and symlink swaps, as
/// done by editors and Kubernetes secret mounts, are noticed.
pub(crate) fn watch_reloads(
    store: Arc<CertStore>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<tokio::task::JoinHandle<()>> {
    let (tx, mut events) = mpsc::unbounded_channel::<()>();
    let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        if event.is_ok_and(|e| !e.kind.is_access()) {
            let _ = tx.send(());
        }
    })
    .map_err(io::Error::other)?;
    for file in [&store.cert, &store.key] {
        let dir = file
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        watcher
            .watch(dir, RecursiveMode::NonRecursive)
            .map_err(io::Error::other)?;
    }
    #[cfg(unix)]
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    Ok(tokio::spawn(async move {
        let _watcher = watcher; // dropping it stops the watch
        loop {
            #[cfg(unix)]
            let hup = hangup.recv();
            #[cfg(not(unix))]
            let hup = std::future::pending::<Option<()>>();
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = hup => {}
                event = events.recv() => {
                    if event.is_none() { break }
                    // Coalesce the burst, then reload once.
                    tokio::time::sleep(DEBOUNCE).await;
                    while events.try_recv().is_ok() {}
                }
            }
            store.reload();
        }
    }))
}
