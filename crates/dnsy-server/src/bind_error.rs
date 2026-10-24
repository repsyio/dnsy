//! Actionable listener bind failures.

use std::io;
use std::net::SocketAddr;

/// Wraps a failed bind of `addr` for the listener configured under `key` (for example
/// `dns.udp`) into an error that names the protocol and address and hints at the fix. The
/// error keeps the original [`io::ErrorKind`].
#[must_use]
pub fn bind_error(protocol: &str, key: &str, addr: SocketAddr, err: &io::Error) -> io::Error {
    let env = format!("DNSY_{}", key.to_ascii_uppercase().replace('.', "__"));
    let override_hint = format!("set `{key}` in the config file or {env} to another address");
    let hint = match err.kind() {
        io::ErrorKind::AddrInUse if addr.port() == 53 => format!(
            "another resolver holds this port (systemd-resolved listens on 127.0.0.53 and \
             127.0.0.54, which collides with 0.0.0.0:53); stop it, or {override_hint}, \
             for example a specific address or a port above 1024"
        ),
        io::ErrorKind::AddrInUse => {
            format!("another process already listens there; stop it, or {override_hint}")
        }
        io::ErrorKind::PermissionDenied if addr.port() < 1024 => format!(
            "ports below 1024 need root or CAP_NET_BIND_SERVICE; grant the capability, run \
             as root, or {override_hint} with a port above 1024"
        ),
        io::ErrorKind::PermissionDenied => {
            format!("check the process may bind it; {override_hint}")
        }
        io::ErrorKind::AddrNotAvailable => {
            format!("that address does not exist on this host; {override_hint}")
        }
        _ => override_hint,
    };
    io::Error::new(
        err.kind(),
        format!("cannot bind {protocol} listener on {addr}: {err} ({hint})"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(kind: io::ErrorKind, addr: &str) -> String {
        let err = io::Error::from(kind);
        let wrapped = bind_error("udp", "dns.udp", addr.parse().unwrap(), &err);
        assert_eq!(wrapped.kind(), kind);
        wrapped.to_string()
    }

    #[test]
    fn port_53_in_use_names_systemd_resolved_and_override() {
        let m = msg(io::ErrorKind::AddrInUse, "0.0.0.0:53");
        assert!(m.contains("udp listener on 0.0.0.0:53"), "{m}");
        assert!(m.contains("systemd-resolved"), "{m}");
        assert!(
            m.contains("`dns.udp`") && m.contains("DNSY_DNS__UDP"),
            "{m}"
        );
    }

    #[test]
    fn other_port_in_use_skips_systemd_resolved() {
        let m = msg(io::ErrorKind::AddrInUse, "127.0.0.1:5353");
        assert!(
            m.contains("127.0.0.1:5353") && !m.contains("systemd-resolved"),
            "{m}"
        );
    }

    #[test]
    fn privileged_port_denied_mentions_capability() {
        let m = msg(io::ErrorKind::PermissionDenied, "0.0.0.0:853");
        assert!(
            m.contains("CAP_NET_BIND_SERVICE") && m.contains("DNSY_DNS__UDP"),
            "{m}"
        );
        let m = msg(io::ErrorKind::PermissionDenied, "0.0.0.0:8053");
        assert!(!m.contains("CAP_NET_BIND_SERVICE"), "{m}");
    }

    #[test]
    fn unavailable_and_other_errors_still_hint_the_override() {
        assert!(msg(io::ErrorKind::AddrNotAvailable, "10.9.9.9:53").contains("does not exist"));
        assert!(msg(io::ErrorKind::Other, "127.0.0.1:53").contains("DNSY_DNS__UDP"));
    }
}
