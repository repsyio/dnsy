use std::net::IpAddr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dnsy_core::UserId;
use dnsy_store::Store;
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::{AuthError, User, UserError, UserService, unix_now};

/// A session expires after this long without use.
pub const IDLE_TIMEOUT_SECS: i64 = 30 * 60;
/// A session expires this long after login regardless of use.
pub const ABSOLUTE_TIMEOUT_SECS: i64 = 12 * 60 * 60;
/// Failed logins allowed per username+IP within [`THROTTLE_WINDOW_SECS`].
pub const MAX_FAILURES: i64 = 5;
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
        self.check_throttle(&name, ip, now).await?;
        match users.verify_password(&name, password).await {
            Ok(user) => {
                self.clear_failures(&name, ip).await?;
                if let Some(prev) = previous {
                    self.destroy(prev).await?;
                }
                let id = self.create_at(user.id, now).await?;
                Ok((id, user))
            }
            Err(UserError::InvalidCredentials) => {
                self.record_failure(&name, ip, now).await?;
                Err(UserError::InvalidCredentials.into())
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn check_throttle(&self, name: &str, ip: IpAddr, now: i64) -> Result<(), AuthError> {
        let (name, ip) = (name.to_owned(), ip.to_string());
        let since = now - THROTTLE_WINDOW_SECS;
        let (count, oldest): (i64, Option<i64>) = self
            .store
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT COUNT(*), MIN(at) FROM login_attempts
                     WHERE username = ?1 AND ip = ?2 AND at > ?3",
                    params![name, ip, since],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?)
            })
            .await?;
        if count >= MAX_FAILURES {
            let wait = oldest.map_or(THROTTLE_WINDOW_SECS, |t| t + THROTTLE_WINDOW_SECS - now);
            return Err(AuthError::Throttled {
                retry_after_secs: u64::try_from(wait.max(1)).unwrap_or(1),
            });
        }
        Ok(())
    }

    async fn record_failure(&self, name: &str, ip: IpAddr, now: i64) -> Result<(), AuthError> {
        let (name, ip) = (name.to_owned(), ip.to_string());
        let since = now - THROTTLE_WINDOW_SECS;
        self.store
            .write(move |tx| {
                tx.execute("DELETE FROM login_attempts WHERE at <= ?1", [since])?;
                tx.execute(
                    "INSERT INTO login_attempts (username, ip, at) VALUES (?1, ?2, ?3)",
                    params![name, ip, now],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    async fn clear_failures(&self, name: &str, ip: IpAddr) -> Result<(), AuthError> {
        let (name, ip) = (name.to_owned(), ip.to_string());
        self.store
            .write(move |tx| {
                tx.execute(
                    "DELETE FROM login_attempts WHERE username = ?1 AND ip = ?2",
                    params![name, ip],
                )?;
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
        self.store
            .write(move |tx| {
                let row: Option<(i64, i64, i64)> = tx
                    .query_row(
                        "SELECT user_id, created_at, last_seen_at FROM sessions WHERE id_sha256 = ?1",
                        [&hash],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .optional()?;
                let Some((user, created_at, last_seen_at)) = row else {
                    return Ok(Err(AuthError::InvalidSession));
                };
                if now - last_seen_at >= IDLE_TIMEOUT_SECS
                    || now - created_at >= ABSOLUTE_TIMEOUT_SECS
                {
                    tx.execute("DELETE FROM sessions WHERE id_sha256 = ?1", [&hash])?;
                    return Ok(Err(AuthError::InvalidSession));
                }
                tx.execute(
                    "UPDATE sessions SET last_seen_at = ?2 WHERE id_sha256 = ?1",
                    params![hash, now],
                )?;
                Ok(Ok(Session {
                    user: UserId(user),
                    created_at,
                    last_seen_at: now,
                }))
            })
            .await?
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
}
