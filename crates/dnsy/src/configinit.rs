//! `dnsy config init`: writes a commented starter configuration.

use std::io::Write;
use std::path::Path;

use crate::{Error, Result};

/// The annotated example, also shipped as `dnsy.toml` in every release archive.
const STARTER: &str = include_str!("../../../examples/dnsy.toml");

/// Unprivileged starter: high port, loopback only, state in the working directory.
const DEV: &str = r#"# DNSY development configuration written by `dnsy config init --dev`.
# It runs without privileges: DNS on loopback port 5353, state under ./dnsy-data (relative to the
# directory you start dnsy from), public upstreams so queries resolve. Every other key keeps its
# default; see docs/book/src/configuration.md or `dnsy config init` for the full annotated file.

[server]
data_dir = "./dnsy-data"

[dns]
udp = ["127.0.0.1:5353"]
tcp = ["127.0.0.1:5353"]

[api]
listen = ["127.0.0.1:5380"]

[zones]
dir = "./dnsy-data/zones"

[resolver]
upstreams = ["1.1.1.1:53", "9.9.9.9:53"]
"#;

/// Writes the starter configuration to `path`, refusing to replace a file unless `force`.
pub(crate) fn init(path: &Path, dev: bool, force: bool, out: &mut impl Write) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            Error::msg(format!(
                "{} already exists; pass --force to overwrite it",
                path.display()
            ))
        } else {
            Error::msg(format!("cannot write {}: {e}", path.display()))
        }
    })?;
    file.write_all(if dev { DEV } else { STARTER }.as_bytes())?;
    writeln!(out, "wrote {}", path.display())?;
    writeln!(out, "next: dnsy --config {} serve", path.display())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnsy_config::Config;

    fn run(path: &Path, dev: bool, force: bool) -> Result<String> {
        let mut out = Vec::new();
        init(path, dev, force, &mut out)?;
        Ok(String::from_utf8(out).unwrap())
    }

    #[test]
    fn starter_loads_with_the_real_loader() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("etc/dnsy.toml");
        let msg = run(&path, false, false).unwrap();
        assert!(msg.contains("wrote"));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains('#'), "starter is commented");
        let c = Config::load(&path).unwrap();
        assert_eq!(c.resolver.upstreams.len(), 2);
    }

    #[test]
    fn dev_runs_unprivileged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dnsy.toml");
        run(&path, true, false).unwrap();
        let c = Config::load(&path).unwrap();
        for addr in c.dns.udp.iter().chain(&c.dns.tcp).chain(&c.api.listen) {
            assert!(addr.ip().is_loopback(), "{addr}");
            assert!(addr.port() >= 1024, "{addr}");
        }
        assert_eq!(c.dns.udp[0].port(), 5353);
        assert!(c.server.data_dir.is_relative());
        assert!(c.zones.dir.starts_with(&c.server.data_dir));
        assert_eq!(c.resolver.upstreams.len(), 2);
    }

    #[test]
    fn refuses_to_overwrite_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dnsy.toml");
        std::fs::write(&path, "# mine").unwrap();
        let err = run(&path, true, false).unwrap_err().to_string();
        assert!(err.contains("--force"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "# mine");
        run(&path, true, true).unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().contains("5353"));
    }

    #[test]
    fn unwritable_target_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let err = run(dir.path(), false, true).unwrap_err().to_string();
        assert!(err.contains("cannot write"), "{err}");
    }
}
