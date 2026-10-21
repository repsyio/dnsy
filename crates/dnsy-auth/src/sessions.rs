use std::net::IpAddr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dnsy_core::UserId;
use dnsy_core::net::client_key;
use dnsy_store::Store;
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::{AuthError, User, UserService, unix_now};

/// A session expires after this long without use. `dnsy-observe` retention deletes expired
/// rows with copies of both lifetimes; keep them in sync.
pub const IDLE_TIMEOUT_SECS: i64 = 30 * 60;
/// A session expires this long after login regardless of use.
pub const ABSOLUTE_TIMEOUT_SECS: i64 = 12 * 60 * 60;
/// `last_seen_at` is only rewritten when it is older than this, so most requests need no write;
/// the idle timeout is therefore accurate to this many seconds.
pub const LAST_SEEN_GRANULARITY_SECS: i64 = 60;
/// Login attempts allowed per username and client key (IPv4 address or IPv6 `/64`) within
/// [`THROTTLE_WINDOW_SECS`].
pub const MAX_FAILURES: i64 = 5;
/// Attempts on one username, from any addresses, before the per-username backoff starts.
pub const USERNAME_FREE_ATTEMPTS: i64 = 10;
/// Longest wait the per-username backoff imposes.
pub const USERNAME_BACKOFF_CAP_SECS: i64 = 60;
pub const THROTTLE_WINDOW_SECS: i64 = 15 * 60;

/// A live session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub user: UserId,
    pub created_at: i64,
    pub last_seen_at: i64,
}

fn hash_id(id: &str) -> Vec<u8> {
    Sha256::digest(id.as_bytes()).to_vec()
}

/// UI sessions (opaque 256-bit ids, stored hashed) and login throttling.
#[derive(Clone)]
pub struct SessionService {
    store: Store,
}

impl SessionService {
    #[must_use]
    pub fn new(store: Store) -> SessionService {
        SessionService { store }
    }

    /// Check credentials with throttling and open a fresh session. A session id
    /// presented with the login (`previous`) is destroyed: the id is rotated.
    ///
    /// # Errors
    /// [`AuthError::Throttled`] (answer 429 with `Retry-After`),
    /// `AuthError::User(UserError::InvalidCredentials)`, or a store failure.
    pub async fn login(
        &self,
        users: &UserService,
        username: &str,
        password: &str,
        ip: IpAddr,
        previous: Option<&str>,
    ) -> Result<(String, User), AuthError> {
        self.login_at(users, username, password, ip, previous, unix_now())
            .await
    }

    pub(crate) async fn login_at(
        &self,
        users: &UserService,
        username: &str,
        password: &str,
        ip: IpAddr,
        previous: Option<&str>,
        now: i64,
    ) -> Result<(String, User), AuthError> {
        let name = username.trim().to_owned();
        let key = client_key(ip).to_string();
        self.reserve_attempt(&name, &key, now).await?;
        match users.verify_password(&name, password).await {
            Ok(user) => {
                // Correct credentials prove the owner is present: forget the account's failures.
                self.clear_failures(&name).await?;
                if let Some(prev) = previous {
                    self.destroy(prev).await?;
                }
                let id = self.create_at(user.id, now).await?;
                Ok((id, user))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Checks both limits and records the attempt in one write transaction, so concurrent
    /// requests cannot all pass the check before any is recorded. Rejected attempts are not
    /// recorded, so hammering a locked key does not extend the lock.
    ///
    /// 1. At most [`MAX_FAILURES`] attempts per `(username, client key)` per window.
    /// 2. Across all addresses, once a username has [`USERNAME_FREE_ATTEMPTS`] attempts in the
    ///    window, each further attempt must wait `2^n` seconds (capped at
    ///    [`USERNAME_BACKOFF_CAP_SECS`]) after the previous one. It is a delay, never a lockout,
    ///    and correct credentials are delayed the same way.
    async fn reserve_attempt(&self, name: &str, key: &str, now: i64) -> Result<(), AuthError> {
        let (name, key) = (name.to_owned(), key.to_owned());
        let since = now - THROTTLE_WINDOW_SECS;
        let wait = self
            .store
            .write(move |tx| {
                tx.execute("DELETE FROM login_attempts WHERE at <= ?1", [since])?;
                let (per_key, oldest): (i64, Option<i64>) = tx.query_row(
                    "SELECT COUNT(*), MIN(at) FROM login_attempts
                     WHERE username = ?1 AND ip = ?2",
                    params![name, key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                if per_key >= MAX_FAILURES {
                    return Ok(Some(
                        oldest.map_or(THROTTLE_WINDOW_SECS, |t| t + THROTTLE_WINDOW_SECS - now),
                    ));
                }
                let (total, last): (i64, Option<i64>) = tx.query_row(
                    "SELECT COUNT(*), MAX(at) FROM login_attempts WHERE username = ?1",
                    [&name],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                if total >= USERNAME_FREE_ATTEMPTS {
                    let exp = u32::try_from(total - USERNAME_FREE_ATTEMPTS).unwrap_or(u32::MAX);
                    let delay = 1_i64
                        .checked_shl(exp)
                        .unwrap_or(i64::MAX)
                        .min(USERNAME_BACKOFF_CAP_SECS);
                    let remaining = last.map_or(0, |t| t + delay - now);
                    if remaining > 0 {
                        return Ok(Some(remaining));
                    }
                }
                tx.execute(
                    "INSERT INTO login_attempts (username, ip, at) VALUES (?1, ?2, ?3)",
                    params![name, key, now],
                )?;
                Ok(None)
            })
            .await?;
        match wait {
            Some(secs) => Err(AuthError::Throttled {
                retry_after_secs: u64::try_from(secs.max(1)).unwrap_or(1),
            }),
            None => Ok(()),
        }
    }

    async fn clear_failures(&self, name: &str) -> Result<(), AuthError> {
        let name = name.to_owned();
        self.store
            .write(move |tx| {
                tx.execute("DELETE FROM login_attempts WHERE username = ?1", [name])?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    async fn create_at(&self, user: UserId, now: i64) -> Result<String, AuthError> {
        let mut raw = [0u8; 32];
        rand::fill(&mut raw[..]);
        let id = URL_SAFE_NO_PAD.encode(raw);
        let hash = hash_id(&id);
        self.store
            .write(move |tx| {
                tx.execute(
                    "INSERT INTO sessions (id_sha256, user_id, created_at, last_seen_at)
                     VALUES (?1, ?2, ?3, ?3)",
                    params![hash, user.0, now],
                )?;
                Ok(())
            })
            .await?;
        Ok(id)
    }

    /// Look up a session and slide its idle timer.
    ///
    /// # Errors
    /// [`AuthError::InvalidSession`] when unknown or expired (expired ones are deleted).
    pub async fn validate(&self, id: &str) -> Result<Session, AuthError> {
        self.validate_at(id, unix_now()).await
    }

    pub(crate) async fn validate_at(&self, id: &str, now: i64) -> Result<Session, AuthError> {
        let hash = hash_id(id);
        // The common case is a read on a reader connection; the writer is only taken to slide the
        // idle timer (at most once per `LAST_SEEN_GRANULARITY_SECS`) or to delete an expired row.
        let lookup = hash.clone();
        let row: Option<(i64, i64, i64)> = self
            .store
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT s.user_id, s.created_at, s.last_seen_at FROM sessions s
                     JOIN users u ON u.id = s.user_id
                     WHERE s.id_sha256 = ?1 AND u.disabled_at IS NULL",
                    [&lookup],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?)
            })
            .await?;
        let Some((user, created_at, last_seen_at)) = row else {
            return Err(AuthError::InvalidSession);
        };
        if now - last_seen_at >= IDLE_TIMEOUT_SECS || now - created_at >= ABSOLUTE_TIMEOUT_SECS {
            self.store
                .write(move |tx| {
                    tx.execute("DELETE FROM sessions WHERE id_sha256 = ?1", [&hash])?;
                    Ok(())
                })
                .await?;
            return Err(AuthError::InvalidSession);
        }
        if now - last_seen_at < LAST_SEEN_GRANULARITY_SECS {
            return Ok(Session {
                user: UserId(user),
                created_at,
                last_seen_at,
            });
        }
        self.store
            .write(move |tx| {
                tx.execute(
                    "UPDATE sessions SET last_seen_at = ?2 WHERE id_sha256 = ?1",
                    params![hash, now],
                )?;
                Ok(())
            })
            .await?;
        Ok(Session {
            user: UserId(user),
            created_at,
            last_seen_at: now,
        })
    }

    /// End a session (logout). Unknown ids are ignored.
    ///
    /// # Errors
    /// A store failure.
    pub async fn destroy(&self, id: &str) -> Result<(), AuthError> {
        let hash = hash_id(id);
        self.store
            .write(move |tx| {
                tx.execute("DELETE FROM sessions WHERE id_sha256 = ?1", [&hash])?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Destroy every session of `user` (after a password or role change).
    ///
    /// # Errors
    /// A store failure.
    pub async fn destroy_all_for_user(&self, user: UserId) -> Result<(), AuthError> {
        self.store
            .write(move |tx| {
                tx.execute("DELETE FROM sessions WHERE user_id = ?1", [user.0])?;
                Ok(())
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use dnsy_core::Role;

    use crate::UserError;

    use super::*;

    const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    async fn setup() -> (SessionService, UserService, UserId, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("t.db")).unwrap();
        let users = UserService::new(store.clone());
        let u = users.create("alice", "pw", Role::Admin).await.unwrap();
        (SessionService::new(store), users, u.id, dir)
    }

    #[tokio::test]
    async fn destroy_all_for_user_only_hits_that_user() {
        let (s, users, alice, _d) = setup().await;
        let bob = users.create("bob", "pw", Role::Viewer).await.unwrap().id;
        let a1 = s.create_at(alice, unix_now()).await.unwrap();
        let a2 = s.create_at(alice, unix_now()).await.unwrap();
        let b1 = s.create_at(bob, unix_now()).await.unwrap();
        s.destroy_all_for_user(alice).await.unwrap();
        assert!(s.validate(&a1).await.is_err());
        assert!(s.validate(&a2).await.is_err());
        s.validate(&b1).await.unwrap();
    }

    #[tokio::test]
    async fn disabling_a_user_ends_sessions_and_blocks_login() {
        let (s, users, alice, _d) = setup().await;
        let bob = users.create("bob", "pw", Role::Admin).await.unwrap().id;
        let a1 = s.create_at(alice, unix_now()).await.unwrap();
        let b1 = s.create_at(bob, unix_now()).await.unwrap();
        users.set_disabled(alice, true).await.unwrap();
        assert!(matches!(
            s.validate(&a1).await,
            Err(AuthError::InvalidSession)
        ));
        s.validate(&b1).await.unwrap();
        let login = s.login(&users, "alice", "pw", IP, None).await;
        assert!(matches!(
            login,
            Err(AuthError::User(UserError::InvalidCredentials))
        ));
        users.set_disabled(alice, false).await.unwrap();
        assert!(s.validate(&a1).await.is_err(), "old sessions stay gone");
        s.login(&users, "alice", "pw", IP, None).await.unwrap();
    }

    #[tokio::test]
    async fn password_change_destroys_sessions() {
        let (s, users, alice, _d) = setup().await;
        let id = s.create_at(alice, unix_now()).await.unwrap();
        users.set_password(alice, "new-password").await.unwrap();
        assert!(matches!(
            s.validate(&id).await,
            Err(AuthError::InvalidSession)
        ));
    }

    #[tokio::test]
    async fn role_change_destroys_sessions_but_noop_keeps_them() {
        let (s, users, alice, _d) = setup().await;
        users.create("root", "pw", Role::Admin).await.unwrap();
        let id = s.create_at(alice, unix_now()).await.unwrap();
        users.update_role(alice, Role::Admin).await.unwrap();
        s.validate(&id).await.unwrap();
        users.update_role(alice, Role::Viewer).await.unwrap();
        assert!(s.validate(&id).await.is_err());
    }

    #[tokio::test]
    async fn session_idle_and_absolute_expiry() {
        let (s, _u, user, _d) = setup().await;
        let id = s.create_at(user, 0).await.unwrap();
        assert_eq!(id.len(), 43); // 256 bits base64url
        // Activity slides the idle window.
        assert_eq!(
            s.validate_at(&id, IDLE_TIMEOUT_SECS - 1)
                .await
                .unwrap()
                .user,
            user
        );
        s.validate_at(&id, 2 * IDLE_TIMEOUT_SECS - 2).await.unwrap();
        // Idle expiry.
        let idle = s.create_at(user, 0).await.unwrap();
        assert!(matches!(
            s.validate_at(&idle, IDLE_TIMEOUT_SECS).await,
            Err(AuthError::InvalidSession)
        ));
        assert!(matches!(
            s.validate_at(&idle, 1).await,
            Err(AuthError::InvalidSession)
        ));
        // Absolute expiry despite constant activity.
        let abs = s.create_at(user, 0).await.unwrap();
        let mut t = 0;
        while t + 1_000 < ABSOLUTE_TIMEOUT_SECS {
            t += 1_000;
            s.validate_at(&abs, t).await.unwrap();
        }
        assert!(matches!(
            s.validate_at(&abs, ABSOLUTE_TIMEOUT_SECS).await,
            Err(AuthError::InvalidSession)
        ));
        assert!(matches!(
            s.validate_at("bogus", 0).await,
            Err(AuthError::InvalidSession)
        ));
    }

    #[tokio::test]
    async fn login_rotates_session() {
        let (s, users, _user, _d) = setup().await;
        let (old, _) = s
            .login_at(&users, "alice", "pw", IP, None, 10)
            .await
            .unwrap();
        let (new, u) = s
            .login_at(&users, "ALICE", "pw", IP, Some(&old), 20)
            .await
            .unwrap();
        assert_ne!(old, new);
        assert_eq!(u.username, "alice");
        assert!(matches!(
            s.validate_at(&old, 21).await,
            Err(AuthError::InvalidSession)
        ));
        s.validate_at(&new, 21).await.unwrap();
        s.destroy(&new).await.unwrap();
        assert!(matches!(
            s.validate_at(&new, 22).await,
            Err(AuthError::InvalidSession)
        ));
    }

    #[tokio::test]
    async fn login_throttle_kicks_in() {
        let (s, users, _user, _d) = setup().await;
        for i in 0..MAX_FAILURES {
            let r = s.login_at(&users, "alice", "bad", IP, None, 100 + i).await;
            assert!(matches!(
                r,
                Err(AuthError::User(UserError::InvalidCredentials))
            ));
        }
        // Even the right password is refused while throttled.
        let r = s.login_at(&users, "alice", "pw", IP, None, 200).await;
        match r {
            Err(AuthError::Throttled { retry_after_secs }) => {
                assert_eq!(retry_after_secs, 100 + 900 - 200);
            }
            other => panic!("expected throttle, got {other:?}"),
        }
        // Other IP and other user are unaffected.
        let other_ip: IpAddr = "10.0.0.2".parse().unwrap();
        s.login_at(&users, "alice", "pw", other_ip, None, 200)
            .await
            .unwrap();
        // Window passes.
        s.login_at(&users, "alice", "pw", IP, None, 100 + THROTTLE_WINDOW_SECS)
            .await
            .unwrap();
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    async fn bad(s: &SessionService, users: &UserService, from: IpAddr, now: i64) -> AuthError {
        s.login_at(users, "alice", "bad", from, None, now)
            .await
            .unwrap_err()
    }

    #[tokio::test]
    async fn concurrent_attempts_cannot_exceed_limit() {
        let (s, users, _user, _d) = setup().await;
        let tasks = (0..20).map(|_| {
            let (s, users) = (s.clone(), users.clone());
            tokio::spawn(async move { bad(&s, &users, IP, 100).await })
        });
        let results = futures_collect(tasks).await;
        let throttled = results
            .iter()
            .filter(|e| matches!(e, AuthError::Throttled { .. }))
            .count();
        assert_eq!(throttled, 20 - usize::try_from(MAX_FAILURES).unwrap());
    }

    async fn futures_collect(
        tasks: impl Iterator<Item = tokio::task::JoinHandle<AuthError>>,
    ) -> Vec<AuthError> {
        let mut out = Vec::new();
        for t in tasks.collect::<Vec<_>>() {
            out.push(t.await.unwrap());
        }
        out
    }

    #[tokio::test]
    async fn throttle_counts_ipv6_rotation_within_slash64() {
        let (s, users, _user, _d) = setup().await;
        for host in 1..=MAX_FAILURES {
            bad(&s, &users, ip(&format!("2001:db8:0:1::{host:x}")), 100).await;
        }
        // Another address in the same /64 shares the budget; a different /64 does not.
        let r = s
            .login_at(&users, "alice", "pw", ip("2001:db8:0:1:ffff::1"), None, 101)
            .await;
        assert!(matches!(r, Err(AuthError::Throttled { .. })));
        s.login_at(&users, "alice", "pw", ip("2001:db8:0:2::1"), None, 101)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn mapped_ipv4_shares_the_budget_of_the_plain_address() {
        let (s, users, _user, _d) = setup().await;
        for _ in 0..MAX_FAILURES {
            bad(&s, &users, ip("192.0.2.7"), 100).await;
        }
        let r = s
            .login_at(&users, "alice", "pw", ip("::ffff:192.0.2.7"), None, 101)
            .await;
        assert!(matches!(r, Err(AuthError::Throttled { .. })));
    }

    #[tokio::test]
    async fn legitimate_user_logs_in_from_other_address_after_remote_lockout() {
        let (s, users, _user, _d) = setup().await;
        for _ in 0..MAX_FAILURES {
            bad(&s, &users, ip("203.0.113.9"), 100).await;
        }
        assert!(matches!(
            bad(&s, &users, ip("203.0.113.9"), 101).await,
            AuthError::Throttled { .. }
        ));
        s.login_at(&users, "alice", "pw", ip("198.51.100.4"), None, 101)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn distributed_guessing_on_one_username_is_slowed_with_a_capped_delay() {
        let (s, users, _user, _d) = setup().await;
        // Many addresses, each within its own budget: the account still slows down.
        let free = USERNAME_FREE_ATTEMPTS;
        for n in 0..free {
            bad(&s, &users, ip(&format!("198.51.100.{}", n + 1)), 100).await;
        }
        let Err(AuthError::Throttled { retry_after_secs }) = s
            .login_at(&users, "alice", "bad", ip("198.51.100.200"), None, 100)
            .await
        else {
            panic!("expected a backoff");
        };
        assert_eq!(retry_after_secs, 1);
        // Correct credentials during the backoff are delayed too, never exempt.
        let r = s
            .login_at(&users, "alice", "pw", ip("198.51.100.201"), None, 100)
            .await;
        assert!(matches!(r, Err(AuthError::Throttled { .. })));
        // The delay is short and a different user is unaffected.
        s.login_at(&users, "alice", "pw", ip("198.51.100.201"), None, 101)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn username_backoff_grows_but_never_exceeds_the_cap() {
        let (s, users, _user, _d) = setup().await;
        let mut now = 100;
        let mut last = 0;
        for n in 0..40_i64 {
            // Always wait out the previous delay, so every attempt is recorded.
            let from = ip(&format!("10.1.{}.{}", n / 200, n % 200 + 1));
            loop {
                match s.login_at(&users, "alice", "bad", from, None, now).await {
                    Err(AuthError::Throttled { retry_after_secs }) => {
                        last = i64::try_from(retry_after_secs).unwrap();
                        assert!(last <= USERNAME_BACKOFF_CAP_SECS);
                        now += last;
                    }
                    _ => break,
                }
            }
        }
        assert_eq!(last, USERNAME_BACKOFF_CAP_SECS, "delay reached the cap");
    }

    #[tokio::test]
    async fn success_clears_failures() {
        let (s, users, _user, _d) = setup().await;
        for i in 0..MAX_FAILURES - 1 {
            let _ = s.login_at(&users, "alice", "bad", IP, None, i).await;
        }
        s.login_at(&users, "alice", "pw", IP, None, 10)
            .await
            .unwrap();
        let _ = s.login_at(&users, "alice", "bad", IP, None, 11).await;
        s.login_at(&users, "alice", "pw", IP, None, 12)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn validate_writes_last_seen_only_when_it_is_stale() {
        let (s, _u, user, _d) = setup().await;
        let id = s.create_at(user, 1_000).await.unwrap();
        let before = s.store.write_count();
        // Stale (100 s): one write slides the timer.
        let first = s.validate_at(&id, 1_100).await.unwrap();
        assert_eq!(first.last_seen_at, 1_100);
        // Within 60 s of that: served from a reader, nothing is written.
        let second = s.validate_at(&id, 1_110).await.unwrap();
        assert_eq!(second.last_seen_at, 1_100, "the stored value is reported");
        assert_eq!(s.store.write_count() - before, 1, "two requests, one write");
        // A request 60 s after the last write slides it again.
        s.validate_at(&id, 1_160).await.unwrap();
        assert_eq!(s.store.write_count() - before, 2);
    }

    #[tokio::test]
    async fn an_unknown_session_does_not_touch_the_writer() {
        let (s, _u, _user, _d) = setup().await;
        let before = s.store.write_count();
        assert!(s.validate_at("bogus", 5).await.is_err());
        assert_eq!(s.store.write_count(), before);
    }
}
