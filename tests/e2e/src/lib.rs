//! End-to-end harness: starts the real `dnsy` binary with a temporary configuration, zones,
//! certificates and a scriptable fake upstream, and talks to it with test clients built on
//! `dnsy-proto`. Every [`Harness`] owns its temp directory and uses port 0 only, so tests run in
//! parallel.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    reason = "test support code: helpers panic with a message instead of returning errors"
)]

pub mod api;
pub mod clients;
pub mod harness;
pub mod pki;
pub mod upstream;
pub mod zones;

pub use api::{Api, Auth, Resp, Session};
pub use clients::{DohClient, Framed, Token, query, query_edns, udp_exchange, udp_raw, udp_silent};
pub use harness::{Harness, MtlsPolicy, Opts};
pub use pki::{ClientIdentity, Pki};
pub use upstream::{FakeUpstream, Reply};

use std::future::Future;
use std::time::{Duration, Instant};

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Default deadline for waiting on the server.
pub const DEADLINE: Duration = Duration::from_secs(20);

/// Polls `f` every 20 ms until it returns `Some`, panicking with `what` after `deadline`.
pub async fn eventually<T, F, Fut>(deadline: Duration, what: &str, mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let end = Instant::now() + deadline;
    loop {
        if let Some(v) = f().await {
            return v;
        }
        assert!(Instant::now() < end, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
