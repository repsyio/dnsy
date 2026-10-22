//! `dnsy serve`: wires every component and runs until SIGINT/SIGTERM.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use dnsy_api::state::CertReload;
use dnsy_api::{ApiConfig, ApiState};
use dnsy_auth::{ClientCertService, TokenService, UserService};
use dnsy_config::{Config, Mtls};
use dnsy_engine::{Engine, EngineBuilder, Services};
use dnsy_server::{
    Allowlist, DOH_TOKEN_CACHE_CAPACITY, DOH_TOKEN_CACHE_TTL, DohConfig, DotConfig, MtlsMode,
    MtlsVerifier, Server, ServerConfig, TokenAuth,
};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::cli::ServeArgs;
use crate::http;
use crate::{Error, Result, open_store};

/// How often the client-certificate allowlist is reloaded from the database.
const ALLOWLIST_REFRESH: Duration = Duration::from_secs(30);
/// How often the client CA bundle and CRL are re-read.
const CA_REFRESH: Duration = Duration::from_secs(300);
/// How often query-log retention runs.
const RETENTION_INTERVAL: Duration = Duration::from_secs(3600);
/// Longest wait for the query log's final flush.
const FLUSH_WAIT: Duration = Duration::from_secs(10);

/// Starts the cache prefetch workers when `[cache.prefetch]` is enabled; the task is aborted with
/// the other background tasks on shutdown.
fn spawn_prefetch(engine: &Arc<Engine>, config: &Config) -> Option<JoinHandle<()>> {
    if !config.cache.enabled || !config.cache.prefetch.enabled {
        return None;
    }
    let engine = Arc::clone(engine);
    Some(tokio::spawn(async move {
        Box::pin(engine.run_prefetch()).await;
    }))
}

pub(crate) async fn serve(config: Config, config_path: &Path, args: ServeArgs) -> Result<()> {
    warn_unsafe_config(&config);
    let store = open_store(&config)?;
    warn_loose_key_files(&config);
    let mut services = Services::open(&config, &store).await?;
    let querylog_task = services.take_querylog_task();
    let engine = Arc::new(
        EngineBuilder::from_services(&config, &store, &services)
            .await?
            .build_time(crate::build_time())
            .build(),
    );
    let mut background: Vec<JoinHandle<()>> = Vec::new();

    background.extend(spawn_prefetch(&engine, &config));
    // Blocklist refresh, zone hot reload, DNSSEC re-signing and key rollover.
    let mut zone_background = services.spawn_background()?;
    background.append(&mut zone_background.tasks);

    // DNS transports.
    let (server_config, mtls, allowlist) = server_config(&config, &store, &mut background)?;
    let server = Server::start(server_config, Arc::clone(&engine)).await?;

    // API.
    let state = api_state(
        &config,
        &engine,
        &services,
        &store,
        allowlist,
        &mut background,
    )
    .await?;
    let tls = match (&config.api.tls_cert, &config.api.tls_key) {
        (Some(cert), Some(key)) => Some(http::acceptor(cert, key)?),
        _ => None,
    };
    let api_config = ApiConfig {
        tls: tls.is_some(),
        secure_cookies: config.api.secure_cookies.into(),
    };
    let app = dnsy_api::router(state, api_config);
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
            http::HttpLimits::from_config(&config),
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
                reload(&engine, &services, config_path, mtls.as_deref()).await;
            }
        }
    }
    tracing::info!("shutting down");
    server.shutdown().await;
    let _ = stop_api.send(true);
    for task in api_tasks {
        let _ = task.await;
    }
    // Everything that holds the engine must be gone before the query log can finish: the router
    // (through the API state) and the background tasks.
    drop(app);
    for task in background {
        task.abort();
        let _ = task.await;
    }
    drop(zone_background);
    drop(services);
    drop(engine);
    if let Some(task) = querylog_task
        && tokio::time::timeout(FLUSH_WAIT, task).await.is_err()
    {
        tracing::warn!("query log flush timed out");
    }
    if let Err(e) = store.optimize().await {
        tracing::warn!(error = %e, "PRAGMA optimize failed at shutdown");
    }
    tracing::info!("stopped");
    Ok(())
}

/// TLS private keys the server reads, by configuration key, whose mode lets group or others read
/// them (always empty off Unix).
fn loose_key_files(config: &Config) -> Vec<(&'static str, &Path)> {
    let keys = [
        ("api.tls_key", config.api.tls_key.as_deref()),
        ("dot.key", config.dot.key.as_deref()),
        ("doh.key", config.doh.key.as_deref()),
    ];
    keys.into_iter()
        .filter_map(|(name, path)| Some((name, path?)))
        .filter(|(_, path)| is_group_or_world_readable(path))
        .collect()
}

#[cfg(unix)]
fn is_group_or_world_readable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o044 != 0)
}

#[cfg(not(unix))]
fn is_group_or_world_readable(_path: &Path) -> bool {
    false
}

fn warn_loose_key_files(config: &Config) {
    for (name, path) in loose_key_files(config) {
        tracing::warn!(
            key = name,
            path = %path.display(),
            "TLS private key is readable by group or others; run chmod 600"
        );
    }
}

/// Everything the API needs from the running server: the engine as live policy, signing, zones, cache, certificate reload and the retention watch.
async fn api_state(
    config: &Config,
    engine: &Arc<dnsy_engine::Engine>,
    services: &Services,
    store: &dnsy_store::Store,
    allowlist: Option<Allowlist>,
    background: &mut Vec<JoinHandle<()>>,
) -> Result<ApiState> {
    let mut state = ApiState::new(store.clone())
        .with_config(config)
        .with_policy(Arc::clone(engine) as Arc<dyn dnsy_engine::LivePolicy>)
        .with_cert_reload(cert_reload(allowlist, store))
        .with_services(services)
        .with_redact_client_ip(config.querylog.redact_client_ip);
    if config.querylog.enabled {
        // Follows `PATCH /settings` changes of `querylog.retention_days`.
        background.push(dnsy_observe::spawn_retention_watch(
            store.clone(),
            state.settings.retention_updates(),
            RETENTION_INTERVAL,
        ));
    }
    if let Some(code) = UserService::new(store.clone()).start_bootstrap().await? {
        state = state.with_bootstrap(Arc::new(code));
    }
    Ok(state)
}

/// A configured `u32` limit as a `usize`.
fn count(n: u32) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

/// Listener settings from the configuration, plus the mTLS verifier (for SIGHUP reloads).
fn server_config(
    config: &Config,
    store: &dnsy_store::Store,
    background: &mut Vec<JoinHandle<()>>,
) -> Result<(ServerConfig, Option<Arc<MtlsVerifier>>, Option<Allowlist>)> {
    let mut sc = ServerConfig::new(config.dns.udp.clone(), config.dns.tcp.clone());
    sc.tcp_idle = Duration::from_millis(config.limits.tcp_idle_ms);
    sc.max_tcp_conns = count(config.limits.max_tcp_conns);
    sc.max_conns_per_client = count(config.limits.max_conns_per_client);
    sc.udp_in_flight = count(config.limits.udp_in_flight);
    sc.udp_in_flight_per_client = count(config.limits.udp_in_flight_per_client);
    sc.udp_sockets_per_address = config.server.udp_sockets_per_address;
    let mut verifier = None;
    let mut list = None;
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
            let v = MtlsVerifier::new(
                mode,
                ca,
                config.dot.client_crl.as_deref(),
                Some(allowlist.clone()),
            )?;
            list = Some(allowlist);
            background.push(v.spawn_reload(CA_REFRESH));
            dot = dot.with_mtls(Arc::clone(&v));
            verifier = Some(v);
        }
        sc.dot = Some(dot);
    }
    if !config.doh.listen.is_empty() {
        let (cert, key) = tls_files(config.doh.cert.as_ref(), config.doh.key.as_ref(), "doh")?;
        let auth = Arc::new(TokenAuth(
            TokenService::new(store.clone())
                .with_cache(DOH_TOKEN_CACHE_TTL, DOH_TOKEN_CACHE_CAPACITY),
        ));
        let mut doh = DohConfig::new(config.doh.listen.clone(), cert, key, auth);
        doh.require_token = config.doh.require_token;
        doh.path.clone_from(&config.doh.path);
        doh.trusted_proxies.clone_from(&config.doh.trusted_proxies);
        sc.doh = Some(doh);
    }
    Ok((sc, verifier, list))
}

/// Reloads the `DoT` fingerprint allowlist from the database after a client-certificate change
/// through the API; that bumps its generation, so open connections are re-checked. Without mTLS
/// there is no allowlist and nothing to reload.
fn cert_reload(allowlist: Option<Allowlist>, store: &dnsy_store::Store) -> CertReload {
    let service = ClientCertService::new(store.clone());
    Arc::new(move || {
        let allowlist = allowlist.clone();
        let service = service.clone();
        Box::pin(async move {
            match allowlist {
                Some(list) => list.refresh(&service).await.map_err(|e| e.to_string()),
                None => Ok(()),
            }
        })
    })
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
    engine: &dnsy_engine::Engine,
    services: &Services,
    config_path: &Path,
    mtls: Option<&MtlsVerifier>,
) {
    tracing::info!("reloading (SIGHUP)");
    services.reload().await;
    if let Some(verifier) = mtls {
        match verifier.reload() {
            Ok(()) => tracing::info!("client CA bundle reloaded"),
            Err(e) => tracing::warn!(error = %e, "client CA reload failed; keeping previous"),
        }
    }
    reload_trust_anchors(engine, config_path);
}

/// Re-reads `[dnssec]` from the configuration file and swaps the trust anchors (inline and
/// `trust_anchor_file`) into the engine; mode and negative trust anchors keep their run-time
/// values. A bad file or anchor keeps the previous anchors.
fn reload_trust_anchors(engine: &dnsy_engine::Engine, config_path: &Path) {
    let config = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "configuration reload failed; keeping trust anchors");
            return;
        }
    };
    match engine.reload_trust_anchors(&dnsy_engine::dnssec_options(&config.dnssec)) {
        Ok(()) => tracing::info!("trust anchors reloaded"),
        Err(e) => tracing::warn!(error = %e, "trust anchor reload failed; keeping previous"),
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

/// Logs every non-fatal configuration warning (an open, unlimited resolver on a public listener).
fn warn_unsafe_config(config: &Config) {
    for warning in config.warnings() {
        tracing::warn!("{warning}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnsy_resolver::{UpstreamClient, UpstreamConfig};

    fn engine(config: &Config) -> Arc<Engine> {
        let client = UpstreamClient::new(UpstreamConfig::default()).unwrap();
        Arc::new(EngineBuilder::new(config, client).build())
    }

    async fn started(engine: &Engine) -> bool {
        for _ in 0..100 {
            if engine.prefetch_running() {
                return true;
            }
            tokio::task::yield_now().await;
        }
        false
    }

    #[tokio::test]
    async fn prefetch_task_runs_when_enabled_and_stops_on_abort() {
        let config = Config::default();
        assert!(config.cache.prefetch.enabled);
        let engine = engine(&config);
        let task = spawn_prefetch(&engine, &config).expect("spawned");
        assert!(started(&engine).await);
        task.abort();
        let _ = task.await;
        assert!(!engine.prefetch_running());
    }

    #[tokio::test]
    async fn prefetch_task_not_started_when_disabled() {
        let mut config = Config::default();
        config.cache.prefetch.enabled = false;
        assert!(spawn_prefetch(&engine(&config), &config).is_none());
        let mut config = Config::default();
        config.cache.enabled = false;
        assert!(spawn_prefetch(&engine(&config), &config).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn group_or_world_readable_tls_keys_are_reported() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let key = |name: &str, mode: u32| {
            let p = dir.path().join(name);
            std::fs::write(&p, "key").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            p
        };
        let mut config = Config::default();
        config.api.tls_key = Some(key("api.key", 0o600));
        config.dot.key = Some(key("dot.key", 0o640));
        config.doh.key = Some(key("doh.key", 0o604));
        let loose: Vec<_> = loose_key_files(&config)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(loose, ["dot.key", "doh.key"]);
        // Missing files and unset keys are not this check's business.
        config.dot.key = Some(dir.path().join("absent.key"));
        config.doh.key = None;
        assert_eq!(loose_key_files(&config).len(), 0);
    }
}
