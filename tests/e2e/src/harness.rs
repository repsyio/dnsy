//! Starts the real `dnsy` binary against a temp directory and tears it down again.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

use serde_json::Value;
use tempfile::TempDir;
use tokio::process::{Child, Command};

use crate::clients::{DohClient, Framed, TcpClient};
use crate::pki::Pki;
use crate::upstream::FakeUpstream;
use crate::zones::file_stem;
use crate::{DEADLINE, eventually};

/// Client certificate policy of the `DoT` listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MtlsPolicy {
    Off,
    Optional,
    Required,
}

/// What the harness configures. Start from `Opts::default()` and adjust.
#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "a flat bag of independent switches"
)]
pub struct Opts {
    /// Zone files as `(origin with trailing dot, JSON text)`.
    pub zones: Vec<(String, String)>,
    /// Enables `DoT` with this client certificate policy.
    pub dot: Option<MtlsPolicy>,
    /// Lists the harness client certificate in the fingerprint allowlist (mTLS only).
    pub allow_client_cert: bool,
    /// Enables `DoH`.
    pub doh: bool,
    pub doh_require_token: bool,
    /// Starts a fake upstream and configures it as the only upstream.
    pub upstream: bool,
    pub resolver_timeout_ms: u64,
    pub resolver_attempts: u32,
    /// Queries per second per client (0 disables the limit).
    pub per_client_qps: u32,
    pub tcp_idle_ms: u64,
    /// Domains written to a blocklist file that seeds the filter.
    pub blocked: Vec<String>,
    pub block_mode: &'static str,
    pub cache_min_ttl: u32,
    pub cache_max_ttl: u32,
    /// `(max_stale, answer_ttl, client_timeout_ms)`; `None` disables serve-stale.
    pub serve_stale: Option<(u32, u32, u64)>,
    pub log_level: &'static str,
    /// `off`, `permissive` or `strict`.
    pub validation: &'static str,
    /// Trust anchors (DS records); empty keeps the built-in root anchors.
    pub trust_anchors: Vec<String>,
    /// Serve UDP and TCP on one shared port (picked free beforehand), for tools that retry a
    /// truncated UDP answer on the same port.
    pub same_udp_tcp_port: bool,
    /// Skip creating the admin user and tokens, so the server prints a bootstrap code
    /// ([`Harness::bootstrap_code`]). `api_token` and `doh_token` are empty then.
    pub no_users: bool,
    /// `(min_hits, remaining_ttl_pct)` enables cache prefetch; `None` keeps it off.
    pub prefetch: Option<(u32, u8)>,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            zones: Vec::new(),
            dot: None,
            allow_client_cert: true,
            doh: false,
            doh_require_token: true,
            upstream: false,
            resolver_timeout_ms: 1000,
            resolver_attempts: 1,
            per_client_qps: 0,
            tcp_idle_ms: 10_000,
            blocked: Vec::new(),
            block_mode: "null_ip",
            cache_min_ttl: 0,
            cache_max_ttl: 86_400,
            serve_stale: None,
            log_level: "info",
            validation: "off",
            trust_anchors: Vec::new(),
            same_udp_tcp_port: false,
            no_users: false,
            prefetch: None,
        }
    }
}

impl Opts {
    #[must_use]
    pub fn zone(mut self, origin: &str, json: String) -> Self {
        self.zones.push((origin.to_owned(), json));
        self
    }
}

/// A running server and everything around it. Dropping it kills the process.
pub struct Harness {
    pub dir: TempDir,
    pub pki: Pki,
    pub upstream: Option<FakeUpstream>,
    pub udp: SocketAddr,
    pub tcp: SocketAddr,
    pub dot: Option<SocketAddr>,
    pub doh: Option<SocketAddr>,
    pub api: SocketAddr,
    /// A `dns:query` token for `DoH`.
    pub doh_token: String,
    /// An admin API token.
    pub api_token: String,
    /// Id of the allowlisted client certificate, when one was registered.
    pub client_cert_id: Option<i64>,
    config_path: PathBuf,
    child: Option<Child>,
    http: reqwest::Client,
}

fn binary() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        if let Some(p) = std::env::var_os("DNSY_BIN") {
            return PathBuf::from(p);
        }
        // <target>/<profile>/deps/<test exe> -> <target>/<profile>/dnsy
        let exe = std::env::current_exe().expect("current exe");
        let profile = exe
            .parent()
            .and_then(Path::parent)
            .expect("target profile dir");
        let bin = profile.join("dnsy");
        if !bin.exists() {
            let status = std::process::Command::new(
                std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()),
            )
            .args(["build", "-p", "dnsy"])
            .status()
            .expect("run cargo build");
            assert!(status.success(), "cargo build -p dnsy failed");
        }
        assert!(bin.exists(), "dnsy binary not found at {}", bin.display());
        bin
    })
}

/// A path or string as a TOML basic string.
fn q(s: impl AsRef<str>) -> String {
    serde_json::to_string(s.as_ref()).expect("quote")
}

fn qp(p: &Path) -> String {
    q(p.to_str().expect("utf-8 path"))
}

/// A port that is free for both TCP and UDP on 127.0.0.1 right now.
fn free_port_both() -> u16 {
    loop {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp");
        let port = tcp.local_addr().expect("addr").port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

fn config(dir: &Path, o: &Opts, upstream: Option<SocketAddr>) -> String {
    let lo = "127.0.0.1:0";
    let dns = if o.same_udp_tcp_port {
        format!("127.0.0.1:{}", free_port_both())
    } else {
        lo.to_owned()
    };
    let mut c = format!(
        "[server]\ndata_dir = {data}\n[dns]\nudp = [\"{dns}\"]\ntcp = [\"{dns}\"]\n\
         [api]\nlisten = [\"{lo}\"]\n[zones]\ndir = {zones}\n\
         [dnssec]\nvalidation = \"{validation}\"\n{anchors}\
         [resolver]\ntimeout_ms = {to}\nattempts = {att}\nupstreams = [{ups}]\n\
         [cache]\nmin_ttl = {minttl}\nmax_ttl = {maxttl}\n\
         [cache.prefetch]\n{prefetch}\
         [filter]\nblock_mode = \"{bm}\"\nblocklists = [{lists}]\n\
         [limits]\nper_client_qps = {qps}\ntcp_idle_ms = {idle}\n\
         [logging]\nlevel = \"{lvl}\"\n",
        data = qp(&dir.join("data")),
        zones = qp(&dir.join("zones")),
        to = o.resolver_timeout_ms,
        att = o.resolver_attempts,
        ups = upstream.map(|a| q(a.to_string())).unwrap_or_default(),
        minttl = o.cache_min_ttl,
        maxttl = o.cache_max_ttl,
        bm = o.block_mode,
        lists = if o.blocked.is_empty() {
            String::new()
        } else {
            qp(&dir.join("blocklist.txt"))
        },
        qps = o.per_client_qps,
        idle = o.tcp_idle_ms,
        lvl = o.log_level,
        validation = o.validation,
        prefetch = match o.prefetch {
            Some((hits, pct)) => {
                format!("enabled = true\nmin_hits = {hits}\nremaining_ttl_pct = {pct}\n")
            }
            None => "enabled = false\n".to_owned(),
        },
        anchors = if o.trust_anchors.is_empty() {
            String::new()
        } else {
            format!(
                "trust_anchors = [{}]\n",
                o.trust_anchors.iter().map(q).collect::<Vec<_>>().join(", ")
            )
        },
    );
    match o.serve_stale {
        Some((max, ttl, wait)) => {
            let _ = write!(
                c,
                "[cache.serve_stale]\nenabled = true\nmax_stale = {max}\nanswer_ttl = {ttl}\n\
                 client_timeout_ms = {wait}\n"
            );
        }
        None => c.push_str("[cache.serve_stale]\nenabled = false\n"),
    }
    if let Some(policy) = o.dot {
        let _ = write!(
            c,
            "[dot]\nlisten = [\"{lo}\"]\ncert = {}\nkey = {}\n",
            qp(&dir.join("server.pem")),
            qp(&dir.join("server.key"))
        );
        let mode = match policy {
            MtlsPolicy::Off => "off",
            MtlsPolicy::Optional => "optional",
            MtlsPolicy::Required => "required",
        };
        let _ = write!(
            c,
            "mtls = \"{mode}\"\nclient_ca = {}\n",
            qp(&dir.join("client-ca.pem"))
        );
    }
    if o.doh {
        let _ = write!(
            c,
            "[doh]\nlisten = [\"{lo}\"]\ncert = {}\nkey = {}\nrequire_token = {}\n",
            qp(&dir.join("server.pem")),
            qp(&dir.join("server.key")),
            o.doh_require_token
        );
    }
    c
}

fn cli(bin: &Path, config: &Path) -> Command {
    let mut c = Command::new(bin);
    c.arg("--config").arg(config);
    c.env_remove("DNSY_PASSWORD")
        .env_remove("DNSY_DNSSEC_PASSPHRASE")
        .env_remove("DNSY_TOKEN")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    c
}

async fn run_cli(mut c: Command, args: &[&str]) -> String {
    c.args(args);
    let out = c.output().await.expect("run dnsy");
    assert!(
        out.status.success(),
        "dnsy {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf-8 output")
}

async fn create_token(bin: &Path, config: &Path, name: &str, scopes: &[&str]) -> String {
    let mut args = vec!["token", "create", "--user", "e2e", "--name", name];
    for s in scopes {
        args.extend(["--scope", s]);
    }
    let out = run_cli(cli(bin, config), &args).await;
    out.lines()
        .find_map(|l| l.strip_prefix("secret (shown once): "))
        .expect("token secret in output")
        .trim()
        .to_owned()
}

impl Harness {
    /// Builds the temp directory, creates a user and tokens, starts `dnsy serve` and waits for
    /// its ready file.
    pub async fn start(opts: Opts) -> Harness {
        let upstream = if opts.upstream {
            Some(FakeUpstream::start().await)
        } else {
            None
        };
        Self::start_with(opts, upstream).await
    }

    /// Like [`start`](Self::start) with an upstream the test already scripted (it becomes the
    /// only upstream and `opts.upstream` is ignored).
    pub async fn start_with(opts: Opts, upstream: Option<FakeUpstream>) -> Harness {
        crate::pki::install_provider();
        let bin = binary();
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("zones")).expect("zones dir");
        let pki = Pki::generate();
        pki.write(root);
        for (origin, json) in &opts.zones {
            std::fs::write(
                root.join("zones")
                    .join(format!("{}.json", file_stem(origin))),
                json,
            )
            .expect("write zone");
        }
        if !opts.blocked.is_empty() {
            std::fs::write(root.join("blocklist.txt"), opts.blocked.join("\n") + "\n")
                .expect("write blocklist");
        }
        let config_path = root.join("dnsy.toml");
        std::fs::write(
            &config_path,
            config(root, &opts, upstream.as_ref().map(FakeUpstream::addr)),
        )
        .expect("write config");

        let (doh_token, api_token) = if opts.no_users {
            (String::new(), String::new())
        } else {
            let mut create = cli(bin, &config_path);
            create.env("DNSY_PASSWORD", "e2e-password-1234");
            run_cli(create, &["user", "create", "e2e", "--role", "admin"]).await;
            let doh = create_token(bin, &config_path, "doh", &["dns:query"]).await;
            let api = create_token(
                bin,
                &config_path,
                "api",
                &["admin", "api:read", "api:write"],
            )
            .await;
            (doh, api)
        };

        let ready = root.join("ready.json");
        let log = std::fs::File::create(root.join("dnsy.log")).expect("log file");
        let mut serve = cli(bin, &config_path);
        serve
            .args(["serve", "--ready-file"])
            .arg(&ready)
            .stdout(Stdio::null())
            .stderr(Stdio::from(log));
        let mut child = serve.spawn().expect("spawn dnsy serve");
        let addrs: Value = eventually(DEADLINE * 2, "server ready file", || {
            let exited = child.try_wait().expect("try_wait");
            let text = std::fs::read_to_string(&ready).ok();
            let log = root.join("dnsy.log");
            async move {
                assert!(
                    exited.is_none(),
                    "dnsy exited before becoming ready ({exited:?}):\n{}",
                    std::fs::read_to_string(log).unwrap_or_default()
                );
                text.and_then(|t| serde_json::from_str(&t).ok())
            }
        })
        .await;
        let addr = |k: &str| -> Option<SocketAddr> { addrs[k].get(0)?.as_str()?.parse().ok() };
        let mut h = Harness {
            pki,
            upstream,
            udp: addr("udp").expect("udp addr"),
            tcp: addr("tcp").expect("tcp addr"),
            dot: addr("dot"),
            doh: addr("doh"),
            api: addr("api").expect("api addr"),
            doh_token,
            api_token,
            client_cert_id: None,
            config_path,
            child: Some(child),
            http: reqwest::Client::builder()
                .timeout(DEADLINE)
                .build()
                .expect("http client"),
            dir,
        };
        if opts.dot.is_some_and(|p| p != MtlsPolicy::Off) && opts.allow_client_cert {
            let (status, body) = h
                .api_send(
                    reqwest::Method::POST,
                    "/client-certs",
                    Some(serde_json::json!({
                        "sha256": h.pki.valid_client.fingerprint(),
                        "label": "e2e client",
                    })),
                )
                .await;
            assert_eq!(status, 201, "registering the client certificate: {body}");
            h.client_cert_id = body["id"].as_i64();
        }
        h
    }

    /// Creates another token for the admin user through the CLI (works while the server runs).
    pub async fn new_token(&self, name: &str, scopes: &[&str]) -> String {
        create_token(binary(), &self.config_path, name, scopes).await
    }

    /// Where the temp directory keeps zone files.
    pub fn zones_dir(&self) -> PathBuf {
        self.dir.path().join("zones")
    }

    /// Atomically writes (or replaces) a zone file; the server reloads it by itself.
    pub fn write_zone(&self, origin: &str, json: &str) {
        let target = self.zones_dir().join(format!("{}.json", file_stem(origin)));
        let tmp = self.dir.path().join("zone.tmp");
        std::fs::write(&tmp, json).expect("write zone");
        std::fs::rename(tmp, target).expect("rename zone");
    }

    /// Everything the server logged to stderr so far.
    pub fn logs(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("dnsy.log")).unwrap_or_default()
    }

    pub async fn tcp_client(&self) -> TcpClient {
        Framed::connect_tcp(self.tcp).await
    }

    pub fn doh_client(&self, http2: bool) -> DohClient {
        DohClient::new(&self.pki, self.doh.expect("DoH enabled"), http2)
    }

    /// A request to the REST API (`/api/v1` + `path`) with the admin token.
    pub async fn api_send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut b = self
            .http
            .request(method, format!("http://{}/api/v1{path}", self.api))
            .bearer_auth(&self.api_token);
        if let Some(body) = body {
            b = b.json(&body);
        }
        let resp = b.send().await.expect("API request");
        let status = resp.status().as_u16();
        let text = resp.text().await.expect("API body");
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    /// Sends `SIG` (`HUP`, `TERM`, ...) to the server process.
    pub fn signal(&self, sig: &str) {
        let pid = self
            .child
            .as_ref()
            .and_then(Child::id)
            .expect("server is running");
        let status = std::process::Command::new("kill")
            .args([format!("-{sig}"), pid.to_string()])
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -{sig} {pid} failed");
    }

    /// The server's process id.
    pub fn pid(&self) -> u32 {
        self.child
            .as_ref()
            .and_then(Child::id)
            .expect("server is running")
    }

    /// Whether the server process is still running.
    pub fn is_running(&mut self) -> bool {
        self.child
            .as_mut()
            .is_some_and(|c| c.try_wait().expect("try_wait").is_none())
    }

    /// Sends SIGTERM and waits (with a deadline) for the process to exit.
    pub async fn terminate(&mut self) -> ExitStatus {
        self.signal("TERM");
        let mut child = self.child.take().expect("server is running");
        tokio::time::timeout(DEADLINE, child.wait())
            .await
            .expect("server exits after SIGTERM within the deadline")
            .expect("wait")
    }

    /// The one-time bootstrap code the server printed (needs [`Opts::no_users`]).
    pub async fn bootstrap_code(&self) -> String {
        const MARK: &str = "shown once): ";
        eventually(DEADLINE, "the bootstrap code in the log", || {
            let code = self
                .logs()
                .split_once(MARK)
                .and_then(|(_, rest)| rest.split_whitespace().next().map(str::to_owned));
            async move { code }
        })
        .await
    }

    /// Waits until the log contains `needle`.
    pub async fn wait_for_log(&self, needle: &str) {
        eventually(DEADLINE, &format!("log line `{needle}`"), || {
            let found = self.logs().contains(needle);
            async move { found.then_some(()) }
        })
        .await;
    }

    /// Waits for a log line count to grow beyond `seen` occurrences of `needle`.
    pub async fn wait_for_log_count(&self, needle: &str, seen: usize) {
        eventually(
            Duration::from_secs(20),
            &format!("`{needle}` in the log"),
            || {
                let n = self.logs().matches(needle).count();
                async move { (n > seen).then_some(()) }
            },
        )
        .await;
    }
}
