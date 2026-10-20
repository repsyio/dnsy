//! `dnsy serve`: wires every component and runs until SIGINT/SIGTERM.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use dnsy_api::{ApiConfig, ApiState};
use dnsy_auth::{ClientCertService, TokenService, UserService};
use dnsy_config::{Config, Mtls};
use dnsy_dnssec::RolloverTimings;
use dnsy_engine::EngineBuilder;
use dnsy_proto::Name;
use dnsy_server::{
    Allowlist, DohConfig, DotConfig, MtlsMode, MtlsVerifier, Server, ServerConfig, TokenAuth,
};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::cli::ServeArgs;
use crate::http;
use crate::{Error, Result, open_store};

/// How often due zones are re-signed and key states advanced.
const SIGN_INTERVAL: Duration = Duration::from_secs(60);
/// Assumed time for a new DNSKEY to reach every resolver, on top of its TTL (rollovers).
const KEY_PROPAGATION_S: u32 = 3600;
/// How often the client-certificate allowlist is reloaded from the database.
const ALLOWLIST_REFRESH: Duration = Duration::from_secs(30);
/// How often the client CA bundle and CRL are re-read.
const CA_REFRESH: Duration = Duration::from_secs(300);
/// How often query-log retention runs.
const RETENTION_INTERVAL: Duration = Duration::from_secs(3600);
/// Longest wait for the query log's final flush.
const FLUSH_WAIT: Duration = Duration::from_secs(10);

pub(crate) async fn serve(config: Config, args: ServeArgs) -> Result<()> {
    let store = open_store(&config)?;
    let mut builder = EngineBuilder::from_config(&config, &store).await?;
    let querylog_task = builder.take_querylog_task();
    let engine = Arc::new(builder.build());
    let mut background: Vec<JoinHandle<()>> = Vec::new();

    // Blocklists: refresh on schedule.
    let lists = engine.list_manager().cloned();
    if let Some(lists) = lists.clone() {
        background.push(tokio::spawn(lists.run()));
    }

    // Zones: hot reload from disk, DNSSEC re-signing and key rollover timer.
    let zones = engine.zone_store().cloned();
    let _zone_watcher = match &zones {
        Some(zones) => Some(zones.watch()?),
        None => None,
    };
    let signing = engine.zone_signing().cloned();
    if let (Some(signing), Some(zones)) = (&signing, &zones) {
        background.push(signing.clone().spawn(SIGN_INTERVAL));
        let zones = Arc::clone(zones);
        background.push(
            signing
                .keys()
                .clone()
                .spawn_timer(SIGN_INTERVAL, move |zone| rollover_timings(&zones, zone)),
        );
    }

    if config.querylog.enabled && config.querylog.retention_days > 0 {
        background.push(dnsy_observe::spawn_retention(
            store.clone(),
            Duration::from_secs(u64::from(config.querylog.retention_days) * 86_400),
            RETENTION_INTERVAL,
        ));
    }

    // DNS transports.
    let (server_config, mtls) = server_config(&config, &store, &mut background)?;
    let server = Server::start(server_config, Arc::clone(&engine)).await?;

    // API.
    let mut state = ApiState::new(store.clone())
        .with_cache(Arc::clone(engine.cache()))
        .with_redact_client_ip(config.querylog.redact_client_ip);
    if let Some(zones) = &zones {
        state = state.with_zones(Arc::clone(zones));
    }
    if let Some(code) = UserService::new(store.clone()).start_bootstrap().await? {
        state = state.with_bootstrap(Arc::new(code));
    }
    let tls = match (&config.api.tls_cert, &config.api.tls_key) {
        (Some(cert), Some(key)) => Some(http::acceptor(cert, key)?),
        _ => None,
    };
    let app = dnsy_api::router(state, ApiConfig { tls: tls.is_some() });
    let (stop_api, stop_rx) = watch::channel(false);
    let mut api_addrs = Vec::new();
    let mut api_tasks = Vec::new();
    for addr in &config.api.listen {
        let listener = TcpListener::bind(addr).await?;
        api_addrs.push(listener.local_addr()?);
        api_tasks.push(tokio::spawn(http::serve(
            listener,
            app.clone(),
            tls.clone(),
            stop_rx.clone(),
        )));
    }

    log_listeners(&server, &api_addrs);
    if let Some(path) = &args.ready_file {
        write_ready_file(path, &server, &api_addrs)?;
    }

    // Run until told to stop; SIGHUP reloads.
    let mut signals = Signals::new()?;
    loop {
        match signals.next().await {
            Event::Stop => break,
            Event::Reload => {
                reload(
                    zones.as_deref(),
                    mtls.as_deref(),
                    lists.as_ref(),
                    signing.as_ref(),
                    &config,
                )
                .await;
            }
        }
    }
    tracing::info!("shutting down");
    server.shutdown().await;
    let _ = stop_api.send(true);
    for task in api_tasks {
        let _ = task.await;
    }
    for task in &background {
        task.abort();
    }
    drop(engine);
    if let Some(task) = querylog_task
        && tokio::time::timeout(FLUSH_WAIT, task).await.is_err()
    {
        tracing::warn!("query log flush timed out");
    }
    tracing::info!("stopped");
    Ok(())
}

/// Rollover timings of `zone` from its signing policy; `None` skips zones that no longer exist.
fn rollover_timings(zones: &dnsy_zone::ZoneStore, zone: &str) -> Option<RolloverTimings> {
    let name = Name::from_ascii(zone).ok()?.to_lowercase();
    let snapshot = zones.snapshot();
    let policy = snapshot.get(&name)?.dnssec.as_ref()?;
    Some(RolloverTimings {
        dnskey_ttl: policy.dnskey_ttl,
        propagation: KEY_PROPAGATION_S,
        max_signature_validity: policy.signature_validity_days.saturating_mul(86_400),
    })
}

/// Listener settings from the configuration, plus the mTLS verifier (for SIGHUP reloads).
fn server_config(
    config: &Config,
    store: &dnsy_store::Store,
    background: &mut Vec<JoinHandle<()>>,
) -> Result<(ServerConfig, Option<Arc<MtlsVerifier>>)> {
    let mut sc = ServerConfig::new(config.dns.udp.clone(), config.dns.tcp.clone());
    sc.tcp_idle = Duration::from_millis(config.limits.tcp_idle_ms);
    sc.max_tcp_conns = usize::try_from(config.limits.max_tcp_conns).unwrap_or(usize::MAX);
    let mut verifier = None;
    if !config.dot.listen.is_empty() {
        let (cert, key) = tls_files(config.dot.cert.as_ref(), config.dot.key.as_ref(), "dot")?;
        let mut dot = DotConfig::new(config.dot.listen.clone(), cert, key);
        let mode = match config.dot.mtls {
            Mtls::Off => None,
            Mtls::Optional => Some(MtlsMode::Optional),
            Mtls::Required => Some(MtlsMode::Required),
        };
        if let Some(mode) = mode {
            let ca = config
                .dot
                .client_ca
                .as_deref()
                .ok_or_else(|| Error::msg("dot.client_ca is required for mtls"))?;
            let allowlist = Allowlist::new();
            background.push(
                allowlist.spawn_refresh(ClientCertService::new(store.clone()), ALLOWLIST_REFRESH),
            );
            let v = MtlsVerifier::new(mode, ca, None, Some(allowlist))?;
            background.push(v.spawn_reload(CA_REFRESH));
            dot = dot.with_mtls(Arc::clone(&v));
            verifier = Some(v);
        }
        sc.dot = Some(dot);
    }
    if !config.doh.listen.is_empty() {
        let (cert, key) = tls_files(config.doh.cert.as_ref(), config.doh.key.as_ref(), "doh")?;
        let auth = Arc::new(TokenAuth(TokenService::new(store.clone())));
        let mut doh = DohConfig::new(config.doh.listen.clone(), cert, key, auth);
        doh.require_token = config.doh.require_token;
        sc.doh = Some(doh);
    }
    Ok((sc, verifier))
}

fn tls_files(
    cert: Option<&std::path::PathBuf>,
    key: Option<&std::path::PathBuf>,
    section: &str,
) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    match (cert, key) {
        (Some(c), Some(k)) => Ok((c.clone(), k.clone())),
        _ => Err(Error::msg(format!(
            "{section}.cert and {section}.key are required"
        ))),
    }
}

/// SIGHUP: re-read what lives on disk or in the database. Changes to the configuration file
/// itself need a restart. TLS certificates reload on their own SIGHUP listener and file watcher.
async fn reload(
    zones: Option<&dnsy_zone::ZoneStore>,
    mtls: Option<&MtlsVerifier>,
    lists: Option<&dnsy_filter::ListManager>,
    signing: Option<&dnsy_zone::ZoneSigning>,
    config: &Config,
) {
    tracing::info!("reloading (SIGHUP)");
    if let Some(zones) = zones {
        match zones.reload() {
            Ok(()) => tracing::info!("zones reloaded"),
            Err(e) => tracing::error!(error = %e, "zone reload failed; keeping previous zones"),
        }
    }
    if let Some(verifier) = mtls {
        match verifier.reload() {
            Ok(()) => tracing::info!("client CA bundle reloaded"),
            Err(e) => tracing::warn!(error = %e, "client CA reload failed; keeping previous"),
        }
    }
    if let Some(lists) = lists
        && let Err(e) = lists.reload().await
    {
        tracing::warn!(error = %e, "blocklist reload failed; keeping previous");
    }
    if let Some(signing) = signing {
        signing.sign_due().await;
    }
    reload_trust_anchors(config.dnssec.trust_anchor_file.as_deref());
}

/// Seam for DNSY-37: the validating forwarder re-reads `[dnssec] trust_anchor_file` here.
/// Until it lands the file is only noted in the log.
fn reload_trust_anchors(file: Option<&Path>) {
    if let Some(file) = file {
        tracing::info!(file = %file.display(), "trust anchor file reload requested (applied once DNSSEC validation is wired)");
    }
}

fn log_listeners(server: &Server, api: &[SocketAddr]) {
    tracing::info!(
        udp = ?server.udp_addrs(),
        tcp = ?server.tcp_addrs(),
        dot = ?server.dot_addrs(),
        doh = ?server.doh_addrs(),
        api = ?api,
        build_time = crate::build_time(),
        "dnsy listening"
    );
}

fn write_ready_file(path: &Path, server: &Server, api: &[SocketAddr]) -> Result<()> {
    let addrs = |a: &[SocketAddr]| a.iter().map(ToString::to_string).collect::<Vec<_>>();
    let json = serde_json::json!({
        "udp": addrs(server.udp_addrs()),
        "tcp": addrs(server.tcp_addrs()),
        "dot": addrs(server.dot_addrs()),
        "doh": addrs(server.doh_addrs()),
        "api": addrs(api),
    });
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&json)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

enum Event {
    Stop,
    Reload,
}

#[cfg(unix)]
struct Signals {
    term: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
    hup: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl Signals {
    fn new() -> Result<Signals> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Signals {
            term: signal(SignalKind::terminate())?,
            int: signal(SignalKind::interrupt())?,
            hup: signal(SignalKind::hangup())?,
        })
    }

    async fn next(&mut self) -> Event {
        tokio::select! {
            _ = self.term.recv() => Event::Stop,
            _ = self.int.recv() => Event::Stop,
            _ = self.hup.recv() => Event::Reload,
        }
    }
}

#[cfg(not(unix))]
struct Signals;

#[cfg(not(unix))]
impl Signals {
    fn new() -> Result<Signals> {
        Ok(Signals)
    }

    async fn next(&mut self) -> Event {
        let _ = tokio::signal::ctrl_c().await;
        Event::Stop
    }
}
