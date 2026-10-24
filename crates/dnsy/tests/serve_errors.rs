//! `dnsy serve` startup failures and the one-time bootstrap code ordering, on the real binary.

use std::net::{TcpListener, UdpSocket};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

fn q(p: &Path) -> String {
    serde_json::to_string(p.to_str().unwrap()).unwrap()
}

fn config(dir: &TempDir, dns: &str, api: &str) -> std::path::PathBuf {
    let path = dir.path().join("dnsy.toml");
    std::fs::write(
        &path,
        format!(
            "[server]\ndata_dir = {}\n[dns]\nudp = [\"{dns}\"]\ntcp = [\"127.0.0.1:0\"]\n\
             [api]\nlisten = [\"{api}\"]\n[zones]\ndir = {}\n[dnssec]\nvalidation = \"off\"\n",
            q(&dir.path().join("data")),
            q(&dir.path().join("zones"))
        ),
    )
    .unwrap();
    path
}

fn serve_output(config: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dnsy"))
        .arg("-c")
        .arg(config)
        .arg("serve")
        .output()
        .unwrap()
}

#[test]
fn taken_api_port_fails_before_any_bootstrap_code() {
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = taken.local_addr().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = serve_output(&config(&dir, "127.0.0.1:0", &addr.to_string()));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains(&format!("api listener on {addr}")), "{err}");
    assert!(err.contains("DNSY_API__LISTEN"), "{err}");
    assert!(
        !err.contains("bootstrap code"),
        "code shown despite failed start: {err}"
    );
}

#[cfg(unix)]
#[test]
fn unwritable_zones_dir_names_the_path_and_fix() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&dir, "127.0.0.1:0", "127.0.0.1:0");
    let locked = dir.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::create_dir(locked.join("probe")).is_ok() {
        return; // running as root: permissions are not enforced
    }
    let text = std::fs::read_to_string(&cfg)
        .unwrap()
        .replace(&q(&dir.path().join("zones")), &q(&locked.join("zones")));
    std::fs::write(&cfg, text).unwrap();
    let out = serve_output(&cfg);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        err.contains("locked/zones") && err.contains("DNSY_ZONES__DIR"),
        "{err}"
    );
    assert!(!err.contains("bootstrap code"), "{err}");
}

#[test]
fn taken_udp_port_fails_before_any_bootstrap_code() {
    let taken = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = taken.local_addr().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = serve_output(&config(&dir, &addr.to_string(), "127.0.0.1:0"));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains(&format!("udp listener on {addr}")), "{err}");
    assert!(err.contains("DNSY_DNS__UDP"), "{err}");
    assert!(
        !err.contains("bootstrap code"),
        "code shown despite failed start: {err}"
    );
}

#[test]
fn successful_start_shows_the_bootstrap_code_once() {
    let dir = tempfile::tempdir().unwrap();
    let ready = dir.path().join("ready.json");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dnsy"))
        .arg("-c")
        .arg(config(&dir, "127.0.0.1:0", "127.0.0.1:0"))
        .arg("serve")
        .arg("--ready-file")
        .arg(&ready)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !ready.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ready.exists(), "server did not become ready");
    child.kill().unwrap();
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(err.matches("One-time bootstrap code").count(), 1, "{err}");
}
