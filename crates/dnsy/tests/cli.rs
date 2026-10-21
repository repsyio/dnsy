//! Runs the real binary: CLI subcommands and `serve` (all listeners on port 0).

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dnsy_proto::{Class, Message, Name, Question, RData, Rcode, RecordType};
use tempfile::TempDir;

const ZONE: &str = r#"{
  "schema": 1,
  "origin": "example.test.",
  "default_ttl": 300,
  "soa": {"mname": "ns1.example.test.", "rname": "hostmaster.example.test.",
          "serial": 1, "refresh": 7200, "retry": 3600, "expire": 1209600, "minimum": 300},
  "records": [{"name": "www", "type": "A", "value": "192.0.2.7"}],
  "dnssec": {"enabled": SIGNED}
}"#;

/// A path as a TOML basic string.
fn q(p: &Path) -> String {
    serde_json::to_string(p.to_str().unwrap()).unwrap()
}

struct Env {
    dir: TempDir,
}

impl Env {
    fn new(signed: bool) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let zones = dir.path().join("zones");
        std::fs::create_dir(&zones).unwrap();
        std::fs::write(
            zones.join("example.test.json"),
            ZONE.replace("SIGNED", &signed.to_string()),
        )
        .unwrap();
        let config = format!(
            "[server]\ndata_dir = {data}\n[dns]\nudp = [\"127.0.0.1:0\"]\ntcp = [\"127.0.0.1:0\"]\n\
             [api]\nlisten = [\"127.0.0.1:0\"]\n[zones]\ndir = {zones}\n\
             [dnssec]\nvalidation = \"off\"\n",
            data = q(&dir.path().join("data")),
            zones = q(&zones),
        );
        std::fs::write(dir.path().join("dnsy.toml"), config).unwrap();
        Env { dir }
    }

    fn append_config(&self, extra: &str) {
        let mut text = std::fs::read_to_string(self.config()).unwrap();
        text.push_str(extra);
        std::fs::write(self.config(), text).unwrap();
    }

    fn config(&self) -> PathBuf {
        self.dir.path().join("dnsy.toml")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_dnsy"));
        c.arg("--config").arg(self.config()).args(args);
        c.env_remove("DNSY_PASSWORD")
            .env_remove("DNSY_DNSSEC_PASSPHRASE")
            .env_remove("DNSY_TOKEN");
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn serve(&self) -> Running {
        let ready = self.dir.path().join("ready.json");
        let child = self
            .command(&["serve", "--ready-file", ready.to_str().unwrap()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let addrs = loop {
            if let Ok(text) = std::fs::read_to_string(&ready) {
                break serde_json::from_str::<serde_json::Value>(&text).unwrap();
            }
            assert!(Instant::now() < deadline, "server did not become ready");
            std::thread::sleep(Duration::from_millis(50));
        };
        let addr = |k: &str| -> SocketAddr { addrs[k][0].as_str().unwrap().parse().unwrap() };
        Running {
            udp: addr("udp"),
            tcp: addr("tcp"),
            api: addr("api"),
            ready: addrs.clone(),
            child,
        }
    }
}

struct Running {
    udp: SocketAddr,
    tcp: SocketAddr,
    api: SocketAddr,
    ready: serde_json::Value,
    child: Child,
}

impl Running {
    fn signal(&self, name: &str) {
        let status = Command::new("kill")
            .args([name, &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn wait_exit(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "server did not exit");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn query(name: &str) -> Vec<u8> {
    let mut m = Message::response_to(&Message::decode(&[0; 12]).unwrap());
    m.header.qr = false;
    m.header.rd = true;
    m.header.id = 0x4242;
    m.questions.push(Question {
        name: Name::from_ascii(name).unwrap(),
        qtype: RecordType::A,
        qclass: Class::In,
    });
    m.encode(512).unwrap()
}

fn udp_ask(addr: SocketAddr, name: &str) -> Message {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock.send_to(&query(name), addr).unwrap();
    let mut buf = [0_u8; 4096];
    let n = sock.recv(&mut buf).unwrap();
    Message::decode(&buf[..n]).unwrap()
}

fn tcp_ask(addr: SocketAddr, name: &str) -> Message {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let q = query(name);
    s.write_all(&u16::try_from(q.len()).unwrap().to_be_bytes())
        .unwrap();
    s.write_all(&q).unwrap();
    let mut len = [0_u8; 2];
    s.read_exact(&mut len).unwrap();
    let mut buf = vec![0_u8; usize::from(u16::from_be_bytes(len))];
    s.read_exact(&mut buf).unwrap();
    Message::decode(&buf).unwrap()
}

fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

fn first_a(m: &Message) -> Option<std::net::Ipv4Addr> {
    m.answers.iter().find_map(|r| match &r.data {
        RData::A(a) => Some(*a),
        _ => None,
    })
}

#[test]
fn config_check_reports_errors() {
    let env = Env::new(false);
    assert!(env.ok(&["config", "check"]).contains("ok"));

    std::fs::write(env.config(), "[dns]\nbogus_key = 1\n").unwrap();
    let out = env.run(&["config", "check"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("bogus_key"));

    let zones = env.dir.path().join("zones");
    let zones_q = q(&zones);
    std::fs::write(
        env.config(),
        format!(
            "[zones]\ndir = {zones_q}\n[dot]\nlisten = [\"127.0.0.1:0\"]\ncert = \"/nonexistent/c.pem\"\nkey = \"/nonexistent/k.pem\"\n"
        ),
    )
    .unwrap();
    let out = env.run(&["config", "check"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("dot.cert"));

    std::fs::write(zones.join("broken.json"), "{ nope").unwrap();
    std::fs::write(env.config(), format!("[zones]\ndir = {}\n", q(&zones))).unwrap();
    let out = env.run(&["config", "check"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("broken.json"));

    let missing = Command::new(env!("CARGO_BIN_EXE_dnsy"))
        .args(["--config", "/nonexistent/dnsy.toml", "config", "check"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
}

#[test]
fn config_check_reports_bad_trust_anchor() {
    let env = Env::new(false);
    let bad = "dnssec_anchor_flip_and_fail";
    std::fs::write(
        env.config(),
        format!("[dnssec]\ntrust_anchors = [\"1 8 2 {bad}\"]\n"),
    )
    .unwrap();
    let out = env.run(&["config", "check"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("trust anchor"), "{stderr}");

    std::fs::write(env.config(), "[dnssec]\ntrust_anchors = [\"1 8 2 abcd\"]\n").unwrap();
    let out = env.run(&["config", "check"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("digest length"));
}

#[test]
fn example_config_is_valid() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/dnsy.toml");
    let text = std::fs::read_to_string(example).unwrap();
    dnsy_config::Config::from_toml(&text).unwrap();
}

#[test]
fn openapi_subcommand_matches_committed() {
    let env = Env::new(false);
    let printed = env.ok(&["openapi"]);
    let committed = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../openapi/dnsy.json"),
    )
    .unwrap();
    assert_eq!(printed.trim_end(), committed.trim_end());
}

#[test]
fn version_prints_build_time() {
    let env = Env::new(false);
    let out = env.ok(&["version"]);
    assert!(out.starts_with(&format!("dnsy {}", env!("CARGO_PKG_VERSION"))));
    assert!(out.contains("built "));
}

#[test]
fn migrate_status_does_not_create_the_database() {
    let env = Env::new(false);
    let status = env.ok(&["migrate", "--status"]);
    assert!(status.contains("pending") && !status.contains("applied"));
    assert!(!env.dir.path().join("data/dnsy.db").exists());
    env.ok(&["migrate"]);
    let status = env.ok(&["migrate", "--status"]);
    assert!(status.contains("applied") && !status.contains("pending"));
}

#[test]
fn db_check_vacuum_and_backup_offline() {
    let env = Env::new(false);
    env.ok(&["migrate"]);
    assert_eq!(env.ok(&["db", "check"]).trim(), "ok");
    assert_eq!(env.ok(&["db", "check", "--full"]).trim(), "ok");
    assert!(env.ok(&["db", "vacuum"]).starts_with("vacuumed: "));
    let copy = env.dir.path().join("copy.db");
    env.ok(&["db", "backup", copy.to_str().unwrap()]);
    let again = env.run(&["db", "backup", copy.to_str().unwrap()]);
    assert!(
        !again.status.success(),
        "an existing file is never overwritten"
    );
    assert!(copy.exists());
}

#[test]
fn db_check_fails_on_a_corrupted_file() {
    let env = Env::new(false);
    env.ok(&["migrate"]);
    std::fs::write(env.dir.path().join("data/dnsy.db"), vec![0x42; 30_000]).unwrap();
    let out = env.run(&["db", "check"]);
    assert!(!out.status.success());
}

#[test]
fn db_backup_works_and_vacuum_refuses_while_the_server_runs() {
    let env = Env::new(false);
    let mut server = env.serve();
    let copy = env.dir.path().join("live.db");
    env.ok(&["db", "backup", copy.to_str().unwrap()]);
    let vacuum = env.run(&["db", "vacuum"]);
    assert!(!vacuum.status.success());
    assert!(String::from_utf8_lossy(&vacuum.stderr).contains("stop it"));
    server.child.kill().unwrap();
    server.child.wait().unwrap();
    assert_eq!(env.ok(&["db", "check"]).trim(), "ok");
}

#[test]
fn users_and_tokens() {
    let env = Env::new(false);
    let mut create = env
        .command(&[
            "user",
            "create",
            "alice",
            "--role",
            "operator",
            "--password-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    create
        .stdin
        .take()
        .unwrap()
        .write_all(b"correct horse battery\n")
        .unwrap();
    assert!(create.wait_with_output().unwrap().status.success());

    let generated = env.ok(&["user", "create", "bob", "--role", "viewer"]);
    assert!(generated.contains("password (shown once)"));
    assert!(
        !env.run(&["user", "create", "carol", "--role", "root"])
            .status
            .success()
    );
    assert!(
        !env.run(&["user", "create", "alice"]).status.success(),
        "duplicate"
    );

    let list = env.ok(&["user", "list"]);
    assert!(list.contains("alice") && list.contains("bob"));

    assert!(
        env.ok(&["user", "reset-password", "bob"])
            .contains("shown once")
    );
    assert!(
        !env.run(&["user", "reset-password", "nobody"])
            .status
            .success()
    );

    let token = env.ok(&[
        "token",
        "create",
        "--user",
        "alice",
        "--name",
        "ci",
        "--scope",
        "api:write",
        "--scope",
        "dns:query",
        "--expires-days",
        "30",
    ]);
    let secret = token.split("shown once): ").nth(1).unwrap().trim();
    assert!(secret.starts_with("dnsy_"), "{secret}");
    assert!(
        !env.run(&[
            "token", "create", "--user", "bob", "--name", "x", "--scope", "admin"
        ])
        .status
        .success(),
        "viewer cannot hold admin"
    );
    assert!(
        !env.run(&[
            "token", "create", "--user", "bob", "--name", "x", "--scope", "bogus"
        ])
        .status
        .success()
    );
}

/// Runs a command with extra environment variables and optional stdin.
fn run_with(env: &Env, vars: &[(&str, &str)], stdin: Option<&str>, args: &[&str]) -> Output {
    let mut c = env.command(args);
    for (k, v) in vars {
        c.env(k, v);
    }
    c.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    let mut pipe = child.stdin.take().unwrap();
    if let Some(text) = stdin {
        pipe.write_all(text.as_bytes()).unwrap();
    }
    drop(pipe);
    child.wait_with_output().unwrap()
}

#[test]
fn user_disable_and_enable() {
    let env = Env::new(false);
    let create = |name: &str, role: &str| {
        let out = run_with(
            &env,
            &[],
            Some("a-long-password\n"),
            &["user", "create", name, "--role", role, "--password-stdin"],
        );
        assert!(out.status.success());
    };
    create("root", "admin");
    create("bob", "viewer");
    assert!(
        !env.run(&["user", "disable", "root"]).status.success(),
        "the last active admin stays enabled"
    );
    assert!(env.ok(&["user", "disable", "bob"]).contains("bob disabled"));
    assert!(env.ok(&["user", "list"]).contains("(disabled)"));
    assert!(!env.run(&["user", "disable", "nobody"]).status.success());
    assert!(env.ok(&["user", "enable", "bob"]).contains("bob enabled"));
    assert!(!env.ok(&["user", "list"]).contains("(disabled)"));
}

#[test]
fn dnssec_ds_confirmed_and_rollover_abort() {
    let env = Env::new(true);
    env.ok(&["zone", "export", "example.test", "--signed"]);
    assert!(
        !env.run(&["dnssec", "ds-confirmed", "example.test"])
            .status
            .success(),
        "nothing waits for a DS"
    );
    assert!(
        !env.run(&["dnssec", "rollover", "abort", "example.test"])
            .status
            .success(),
        "nothing to abort"
    );
    env.ok(&["dnssec", "keys", "rollover", "example.test"]);
    let confirmed = env.ok(&["dnssec", "ds-confirmed", "example.test"]);
    assert!(confirmed.contains("confirmed"), "{confirmed}");
    assert!(
        !env.run(&["dnssec", "ds-confirmed", "example.test"])
            .status
            .success(),
        "already confirmed"
    );
    assert!(
        !env.run(&[
            "dnssec",
            "rollover",
            "abort",
            "example.test",
            "--role",
            "xsk"
        ])
        .status
        .success()
    );
    assert!(
        !env.run(&[
            "dnssec",
            "rollover",
            "abort",
            "example.test",
            "--role",
            "zsk"
        ])
        .status
        .success(),
        "no zsk rollover"
    );
    let aborted = env.ok(&["dnssec", "rollover", "abort", "example.test"]);
    assert!(
        aborted.contains("aborted csk rollover") && aborted.contains("remove it at the registrar"),
        "{aborted}"
    );
    let keys = env.ok(&["dnssec", "keys", "list", "example.test"]);
    assert!(
        keys.contains("removed") && keys.contains("active"),
        "{keys}"
    );
    env.ok(&["dnssec", "keys", "rollover", "example.test"]);
    let ds = env.run(&["dnssec", "ds-confirmed", "example.test", "--key", "99"]);
    assert!(!ds.status.success());
}

#[test]
fn dnssec_key_backup_and_restore() {
    let env = Env::new(true);
    env.ok(&["zone", "export", "example.test", "--signed"]);
    let file = env.dir.path().join("keys.bundle");
    let file_arg = file.to_str().unwrap();
    let pass = ("DNSY_DNSSEC_BACKUP_PASSPHRASE", "backup-pass-phrase");

    assert!(
        !env.run(&["dnssec", "keys", "export", file_arg])
            .status
            .success(),
        "no passphrase"
    );
    let short = run_with(
        &env,
        &[("DNSY_DNSSEC_BACKUP_PASSPHRASE", "short")],
        None,
        &["dnssec", "keys", "export", file_arg],
    );
    assert!(!short.status.success());
    let out = run_with(&env, &[pass], None, &["dnssec", "keys", "export", file_arg]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bytes = std::fs::read(&file).unwrap();
    assert!(!bytes.is_empty() && !String::from_utf8_lossy(&bytes).contains("example.test"));
    assert!(
        !run_with(&env, &[pass], None, &["dnssec", "keys", "export", file_arg])
            .status
            .success(),
        "an existing file is never overwritten"
    );

    // Restore into another installation (stdin passphrase), then again: nothing new.
    let other = Env::new(false);
    let wrong = run_with(
        &other,
        &[],
        Some("not-the-passphrase\n"),
        &["dnssec", "keys", "import", file_arg, "--passphrase-stdin"],
    );
    assert!(!wrong.status.success());
    let ok = run_with(
        &other,
        &[],
        Some("backup-pass-phrase\n"),
        &["dnssec", "keys", "import", file_arg, "--passphrase-stdin"],
    );
    assert!(String::from_utf8_lossy(&ok.stdout).contains("1 key(s) imported"));
    let again = run_with(
        &other,
        &[pass],
        None,
        &["dnssec", "keys", "import", file_arg],
    );
    assert!(String::from_utf8_lossy(&again.stdout).contains("0 key(s) imported"));
    let keys = other.ok(&["dnssec", "keys", "list", "example.test"]);
    assert!(keys.contains("csk") && keys.contains("active"), "{keys}");
}

#[test]
fn dnssec_passphrase_change_reencrypts_keys() {
    let env = Env::new(true);
    let old = [("DNSY_DNSSEC_PASSPHRASE", "old-pass-phrase")];
    let new = [("DNSY_DNSSEC_PASSPHRASE", "new-pass-phrase")];
    let export = |vars: &[(&str, &str)]| {
        run_with(
            &env,
            vars,
            None,
            &["zone", "export", "example.test", "--signed"],
        )
    };
    assert!(export(&old).status.success());

    let short = run_with(
        &env,
        &old,
        Some("short\n"),
        &["dnssec", "passphrase", "change", "--new-passphrase-stdin"],
    );
    assert!(!short.status.success());
    let none = run_with(&env, &old, None, &["dnssec", "passphrase", "change"]);
    assert!(!none.status.success(), "no new passphrase given");
    let wrong = run_with(
        &env,
        &[
            ("DNSY_DNSSEC_PASSPHRASE", "wrong-pass-phrase"),
            ("DNSY_DNSSEC_NEW_PASSPHRASE", "new-pass-phrase"),
        ],
        None,
        &["dnssec", "passphrase", "change"],
    );
    assert!(!wrong.status.success(), "the current passphrase is needed");
    assert!(
        export(&old).status.success(),
        "a failed change leaves the keys alone"
    );

    let changed = run_with(
        &env,
        &[old[0], ("DNSY_DNSSEC_NEW_PASSPHRASE", "new-pass-phrase")],
        None,
        &["dnssec", "passphrase", "change"],
    );
    let stdout = String::from_utf8_lossy(&changed.stdout);
    assert!(
        changed.status.success() && stdout.contains("1 key(s) re-encrypted"),
        "{stdout}"
    );
    assert!(!stdout.contains("pass-phrase"));
    assert!(
        !export(&old).status.success(),
        "old passphrase no longer works"
    );
    assert!(export(&new).status.success());
}

#[test]
fn zone_export_and_dnssec_keys() {
    let env = Env::new(true);
    let bind = env.ok(&["zone", "export", "example.test"]);
    assert!(bind.contains("www") && bind.contains("192.0.2.7"));
    assert!(
        !env.run(&["zone", "export", "missing.test"])
            .status
            .success()
    );

    let signed = env.ok(&["zone", "export", "example.test.", "--signed"]);
    assert!(
        signed.contains("RRSIG") && signed.contains("DNSKEY"),
        "{signed}"
    );

    let keys = env.ok(&["dnssec", "keys", "list", "example.test"]);
    assert!(keys.contains("csk") && keys.contains("active"), "{keys}");
    let ds = env.ok(&["dnssec", "keys", "ds", "example.test"]);
    assert_eq!(ds.lines().count(), 2, "{ds}");
    assert!(ds.contains(" 13 2 ") && ds.contains(" 13 4 "));

    let rolled = env.ok(&[
        "dnssec",
        "keys",
        "rollover",
        "example.test",
        "--algorithm",
        "15",
    ]);
    assert!(rolled.contains("rollover started"));
    assert!(
        !env.run(&["dnssec", "keys", "rollover", "example.test"])
            .status
            .success(),
        "second rollover of the same role"
    );
    let generated = env.ok(&[
        "dnssec",
        "keys",
        "generate",
        "example.test",
        "--role",
        "zsk",
    ]);
    assert!(generated.contains("generated key"));
    assert!(
        !env.run(&[
            "dnssec",
            "keys",
            "generate",
            "example.test",
            "--algorithm",
            "8"
        ])
        .status
        .success()
    );
    assert!(
        !env.run(&[
            "dnssec",
            "keys",
            "generate",
            "example.test",
            "--role",
            "xsk"
        ])
        .status
        .success()
    );
    // No keys yet for a zone that never signed.
    assert!(
        !env.run(&["dnssec", "keys", "ds", "other.test"])
            .status
            .success()
    );
    // Unsigned zones cannot export signed.
    let plain = Env::new(false);
    assert!(
        !plain
            .run(&["zone", "export", "example.test", "--signed"])
            .status
            .success()
    );
}

#[test]
fn serve_starts_and_answers_udp() {
    let env = Env::new(false);
    let server = env.serve();
    let answer = udp_ask(server.udp, "www.example.test.");
    assert_eq!(answer.header.id, 0x4242);
    assert_eq!(first_a(&answer), Some("192.0.2.7".parse().unwrap()));
    let answer = tcp_ask(server.tcp, "www.example.test.");
    assert_eq!(first_a(&answer), Some("192.0.2.7".parse().unwrap()));
    // Not ours and no upstreams: the server answers (with a failure) rather than hanging.
    let other = udp_ask(server.udp, "elsewhere.invalid.");
    assert_ne!(other.header.rcode, Rcode::NoError);

    let health = http_get(server.api, "/healthz");
    assert!(
        health.starts_with("HTTP/1.0 200") || health.starts_with("HTTP/1.1 200"),
        "{health}"
    );
    let ready = http_get(server.api, "/readyz");
    assert!(ready.contains("ready"), "{ready}");
}

#[test]
fn cache_flush_through_the_api() {
    let env = Env::new(false);
    let mut create = env
        .command(&["user", "create", "root", "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    create
        .stdin
        .take()
        .unwrap()
        .write_all(b"long enough password\n")
        .unwrap();
    assert!(create.wait().unwrap().success());
    let token = env.ok(&[
        "token",
        "create",
        "--user",
        "root",
        "--name",
        "cli",
        "--scope",
        "api:write",
    ]);
    let secret = token
        .split("shown once): ")
        .nth(1)
        .unwrap()
        .trim()
        .to_owned();

    let server = env.serve();
    let url = format!("http://{}", server.api);
    let flushed = env.ok(&["cache", "flush", "--url", &url, "--token", &secret]);
    assert!(flushed.contains("flushed 0 cache entries"), "{flushed}");
    let flushed = env.ok(&[
        "cache",
        "flush",
        "example.test",
        "--subtree",
        "--url",
        &url,
        "--token",
        &secret,
    ]);
    assert!(flushed.contains("flushed"), "{flushed}");
    let rejected = env.run(&["cache", "flush", "--url", &url, "--token", "dnsy_wrong"]);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("401"));
    let unreachable = env.run(&[
        "cache",
        "flush",
        "--url",
        "http://127.0.0.1:1",
        "--token",
        &secret,
    ]);
    assert!(!unreachable.status.success());
    assert!(
        !env.run(&[
            "cache",
            "flush",
            "--url",
            &url,
            "--token",
            &secret,
            &"a".repeat(70)
        ])
        .status
        .success()
    );
}

#[test]
fn sigterm_graceful() {
    let env = Env::new(false);
    let mut server = env.serve();
    server.signal("-TERM");
    let status = server.wait_exit();
    assert!(status.success(), "{status:?}");
    // The sockets are gone.
    assert!(TcpStream::connect_timeout(&server.api, Duration::from_millis(500)).is_err());
}

#[test]
fn sigint_graceful() {
    let env = Env::new(false);
    let mut server = env.serve();
    server.signal("-INT");
    assert!(server.wait_exit().success());
}

#[test]
fn sighup_reloads_zones_and_keeps_serving() {
    let env = Env::new(false);
    let mut server = env.serve();
    let zone = env.dir.path().join("zones/example.test.json");
    let changed = ZONE
        .replace("SIGNED", "false")
        .replace("192.0.2.7", "192.0.2.99");
    std::fs::write(&zone, changed).unwrap();
    server.signal("-HUP");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let answer = udp_ask(server.udp, "www.example.test.");
        if first_a(&answer) == Some("192.0.2.99".parse().unwrap()) {
            break;
        }
        assert!(Instant::now() < deadline, "zone change not picked up");
        std::thread::sleep(Duration::from_millis(100));
    }
    // A broken zone file keeps the previous zones and the process alive.
    std::fs::write(&zone, "{ broken").unwrap();
    server.signal("-HUP");
    std::thread::sleep(Duration::from_millis(500));
    assert!(server.child.try_wait().unwrap().is_none());
    assert_eq!(
        first_a(&udp_ask(server.udp, "www.example.test.")),
        Some("192.0.2.99".parse().unwrap())
    );
    server.signal("-TERM");
    assert!(server.wait_exit().success());
}

#[test]
fn serve_starts_dot_with_mtls_and_doh() {
    let env = Env::new(false);
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let tls = env.dir.path();
    std::fs::write(tls.join("cert.pem"), cert.cert.pem()).unwrap();
    std::fs::write(tls.join("key.pem"), cert.signing_key.serialize_pem()).unwrap();
    env.append_config(&format!(
        "[dot]\nlisten = [\"127.0.0.1:0\"]\ncert = {c}\nkey = {k}\nmtls = \"required\"\nclient_ca = {c}\n\
         [doh]\nlisten = [\"127.0.0.1:0\"]\ncert = {c}\nkey = {k}\n\
         [api]\nlisten = [\"127.0.0.1:0\"]\ntls_cert = {c}\ntls_key = {k}\n",
        c = q(&tls.join("cert.pem")),
        k = q(&tls.join("key.pem")),
    ));
    // Duplicate [api] table from the base config is a TOML error: drop the base one.
    let base = std::fs::read_to_string(env.config()).unwrap();
    std::fs::write(
        env.config(),
        base.replacen("[api]\nlisten = [\"127.0.0.1:0\"]\n", "", 1),
    )
    .unwrap();
    let mut server = env.serve();
    for key in ["dot", "doh", "api"] {
        let addr: SocketAddr = server.ready[key][0].as_str().unwrap().parse().unwrap();
        TcpStream::connect(addr).unwrap();
    }
    server.signal("-TERM");
    assert!(server.wait_exit().success());
}

#[test]
fn serve_fails_fast_on_missing_certificate() {
    let env = Env::new(false);
    env.append_config("[doh]\nlisten = [\"127.0.0.1:0\"]\ncert = \"/nonexistent/c.pem\"\nkey = \"/nonexistent/k.pem\"\n");
    let out = env.run(&["serve"]);
    assert!(!out.status.success());
}

/// Opens a TLS connection to `addr` trusting `cert_pem` (server name `localhost`).
fn tls_connect(
    addr: SocketAddr,
    cert_pem: &str,
) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    use rustls_pki_types::pem::PemObject as _;
    let mut roots = rustls::RootCertStore::empty();
    for der in rustls_pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes()) {
        roots.add(der.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let conn = rustls::ClientConnection::new(
        Arc::new(config),
        rustls_pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    rustls::StreamOwned::new(conn, tcp)
}

fn dot_ask(addr: SocketAddr, cert_pem: &str, name: &str) -> Message {
    let mut s = tls_connect(addr, cert_pem);
    let q = query(name);
    s.write_all(&u16::try_from(q.len()).unwrap().to_be_bytes())
        .unwrap();
    s.write_all(&q).unwrap();
    let mut len = [0_u8; 2];
    s.read_exact(&mut len).unwrap();
    let mut buf = vec![0_u8; usize::from(u16::from_be_bytes(len))];
    s.read_exact(&mut buf).unwrap();
    Message::decode(&buf).unwrap()
}

/// POSTs a query; returns the HTTP status and the DNS answer when there is one.
fn doh_post(
    addr: SocketAddr,
    cert_pem: &str,
    path: &str,
    bearer: Option<&str>,
    name: &str,
) -> (u16, Option<Message>) {
    let mut s = tls_connect(addr, cert_pem);
    let q = query(name);
    let auth = bearer.map_or_else(String::new, |t| format!("Authorization: Bearer {t}\r\n"));
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\n{auth}Content-Type: application/dns-message\r\n\
         Accept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        q.len()
    )
    .unwrap();
    s.write_all(&q).unwrap();
    let mut raw = Vec::new();
    // The server closes with or without close_notify; keep what arrived either way.
    let _ = s.read_to_end(&mut raw);
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status: u16 = head.split(' ').nth(1).unwrap().parse().unwrap();
    let body = &raw[split + 4..];
    (status, Message::decode(body).ok().filter(|_| status == 200))
}

#[test]
fn dot_and_doh_answer_queries_through_the_binary() {
    let env = Env::new(false);
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_pem = cert.cert.pem();
    let tls = env.dir.path();
    std::fs::write(tls.join("cert.pem"), &cert_pem).unwrap();
    std::fs::write(tls.join("key.pem"), cert.signing_key.serialize_pem()).unwrap();
    env.append_config(&format!(
        "[dot]\nlisten = [\"127.0.0.1:0\"]\ncert = {c}\nkey = {k}\n\
         [doh]\nlisten = [\"127.0.0.1:0\"]\ncert = {c}\nkey = {k}\npath = \"/custom-doh\"\n",
        c = q(&tls.join("cert.pem")),
        k = q(&tls.join("key.pem")),
    ));
    let mut create = env
        .command(&["user", "create", "dohuser", "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    create
        .stdin
        .take()
        .unwrap()
        .write_all(b"long enough password\n")
        .unwrap();
    assert!(create.wait().unwrap().success());
    let out = env.ok(&[
        "token",
        "create",
        "--user",
        "dohuser",
        "--name",
        "doh",
        "--scope",
        "dns:query",
    ]);
    let token = out.split("shown once): ").nth(1).unwrap().trim().to_owned();

    let server = env.serve();
    let addr = |k: &str| -> SocketAddr { server.ready[k][0].as_str().unwrap().parse().unwrap() };
    let expected = Some("192.0.2.7".parse().unwrap());

    assert_eq!(
        first_a(&dot_ask(addr("dot"), &cert_pem, "www.example.test.")),
        expected
    );

    let doh = addr("doh");
    let (status, answer) = doh_post(
        doh,
        &cert_pem,
        "/custom-doh",
        Some(&token),
        "www.example.test.",
    );
    assert_eq!(status, 200);
    assert_eq!(first_a(&answer.unwrap()), expected);
    // The token in the path works, on the configured path only.
    let (status, answer) = doh_post(
        doh,
        &cert_pem,
        &format!("/custom-doh/{token}"),
        None,
        "www.example.test.",
    );
    assert_eq!(status, 200);
    assert_eq!(first_a(&answer.unwrap()), expected);
    assert_eq!(
        doh_post(
            doh,
            &cert_pem,
            "/dns-query",
            Some(&token),
            "www.example.test."
        )
        .0,
        404
    );
    // No token: refused.
    assert_eq!(
        doh_post(doh, &cert_pem, "/custom-doh", None, "www.example.test.").0,
        401
    );
}

/// Sends one JSON request to the API and returns the status line code and body.
fn api(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: &str,
    body: Option<&str>,
) -> (u16, String) {
    let body = body.unwrap_or("");
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "{method} {path} HTTP/1.0\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let status = out.split(' ').nth(1).unwrap().parse().unwrap();
    let body = out
        .split_once("\r\n\r\n")
        .map_or(String::new(), |(_, b)| b.to_owned());
    (status, body)
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end scenario reads top to bottom"
)]
fn api_changes_reach_the_running_server() {
    let env = Env::new(true);
    let mut create = env
        .command(&["user", "create", "root", "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    create
        .stdin
        .take()
        .unwrap()
        .write_all(b"long enough password\n")
        .unwrap();
    assert!(create.wait().unwrap().success());
    let out = env.ok(&[
        "token",
        "create",
        "--user",
        "root",
        "--name",
        "t",
        "--scope",
        "api:read",
        "--scope",
        "api:write",
        "--scope",
        "admin",
    ]);
    let token = out.split("shown once): ").nth(1).unwrap().trim().to_owned();
    let anchors = env.dir.path().join("anchors.ds");
    std::fs::write(
        &anchors,
        "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n",
    )
    .unwrap();
    env.append_config(&format!("[dnssec]\ntrust_anchor_file = {}\n", q(&anchors)));
    // Drop the base [dnssec] table; the appended one replaces it.
    let base = std::fs::read_to_string(env.config()).unwrap();
    std::fs::write(
        env.config(),
        base.replacen("[dnssec]\nvalidation = \"off\"\n", "", 1),
    )
    .unwrap();

    let mut server = env.serve();
    let name = "www.example.test.";

    // ACL changes apply to the live engine (and are undone again).
    let (status, rule) = api(
        server.api,
        "POST",
        "/api/v1/acl",
        &token,
        Some(r#"{"cidr":"127.0.0.1/32","action":"refuse"}"#),
    );
    assert_eq!(status, 201, "{rule}");
    assert_eq!(udp_ask(server.udp, name).header.rcode, Rcode::Refused);
    let id = serde_json::from_str::<serde_json::Value>(&rule).unwrap()["id"]
        .as_i64()
        .unwrap();
    assert_eq!(
        api(
            server.api,
            "DELETE",
            &format!("/api/v1/acl/{id}"),
            &token,
            None
        )
        .0,
        204
    );
    assert_eq!(udp_ask(server.udp, name).header.rcode, Rcode::NoError);

    // Wired components: no 503 for signing, validation settings, certificates and readiness.
    assert_eq!(
        api(
            server.api,
            "GET",
            "/api/v1/zones/example.test/dnssec",
            &token,
            None
        )
        .0,
        200
    );
    let (status, settings) = api(server.api, "GET", "/api/v1/settings/dnssec", &token, None);
    assert_eq!(status, 200, "{settings}");
    let cert = format!(r#"{{"sha256":"{}","label":"x"}}"#, "ab".repeat(32));
    assert_eq!(
        api(
            server.api,
            "POST",
            "/api/v1/client-certs",
            &token,
            Some(&cert)
        )
        .0,
        201
    );
    let (status, ready) = api(server.api, "GET", "/readyz", &token, None);
    assert_eq!(status, 200);
    assert!(!ready.contains("dnssec_clock_untrusted"), "{ready}");

    // SIGHUP reloads the trust anchors from the configuration file.
    server.signal("-HUP");
    std::thread::sleep(Duration::from_millis(500));
    server.signal("-TERM");
    assert!(server.wait_exit().success());
    let mut log = String::new();
    server
        .child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut log)
        .unwrap();
    assert!(log.contains("trust anchors reloaded"), "{log}");
}
