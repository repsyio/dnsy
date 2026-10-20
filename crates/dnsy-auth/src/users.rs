use dnsy_core::{Role, UserId};
use dnsy_store::{Store, StoreError};
use rusqlite::{OptionalExtension, Transaction, params};

use crate::UserError;
use crate::bootstrap::{self, BootstrapCode};
use crate::password::{self, blocking};

/// A stored user (never carries the password hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: UserId,
    pub username: String,
    pub role: Role,
    /// Unix seconds.
    pub created_at: i64,
}

fn role_str(role: Role) -> &'static str {
    match role {
        Role::Admin => "admin",
        Role::Operator => "operator",
        Role::Viewer => "viewer",
    }
}

fn parse_role(s: &str) -> Result<Role, rusqlite::Error> {
    match s {
        "admin" => Ok(Role::Admin),
        "operator" => Ok(Role::Operator),
        "viewer" => Ok(Role::Viewer),
        other => Err(rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Text,
            format!("unknown role {other:?}").into(),
        )),
    }
}

const COLUMNS: &str = "id, username, role, created_at";

fn row_to_user(r: &rusqlite::Row<'_>) -> Result<User, rusqlite::Error> {
    Ok(User {
        id: UserId(r.get(0)?),
        username: r.get(1)?,
        role: parse_role(&r.get::<_, String>(2)?)?,
        created_at: r.get(3)?,
    })
}

fn find(tx: &Transaction<'_>, id: UserId) -> Result<Option<User>, StoreError> {
    Ok(tx
        .query_row(
            &format!("SELECT {COLUMNS} FROM users WHERE id = ?1"),
            [id.0],
            row_to_user,
        )
        .optional()?)
}

fn admin_count_excluding(tx: &Transaction<'_>, id: UserId) -> Result<i64, StoreError> {
    Ok(tx.query_row(
        "SELECT COUNT(*) FROM users WHERE role = 'admin' AND id != ?1",
        [id.0],
        |r| r.get(0),
    )?)
}

fn insert(
    tx: &Transaction<'_>,
    username: &str,
    role: Role,
    hash: &str,
) -> Result<Result<User, UserError>, StoreError> {
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?1)",
        [username],
        |r| r.get(0),
    )?;
    if exists {
        return Ok(Err(UserError::DuplicateUsername));
    }
    tx.execute(
        "INSERT INTO users (username, role, password_hash) VALUES (?1, ?2, ?3)",
        params![username, role_str(role), hash],
    )?;
    let user = tx.query_row(
        &format!("SELECT {COLUMNS} FROM users WHERE id = last_insert_rowid()"),
        [],
        row_to_user,
    )?;
    Ok(Ok(user))
}

fn check_input(username: &str, password: &str) -> Result<(), UserError> {
    if username.trim().is_empty() || password.is_empty() {
        return Err(UserError::Empty);
    }
    Ok(())
}

/// User accounts and credentials.
#[derive(Clone)]
pub struct UserService {
    store: Store,
}

impl UserService {
    #[must_use]
    pub fn new(store: Store) -> UserService {
        UserService { store }
    }

    /// Create a user. Usernames are unique case-insensitively.
    ///
    /// # Errors
    /// [`UserError::Empty`], [`UserError::DuplicateUsername`], or a store failure.
    pub async fn create(
        &self,
        username: &str,
        password: &str,
        role: Role,
    ) -> Result<User, UserError> {
        check_input(username, password)?;
        let hash = hash_off_thread(password).await?;
        let username = username.trim().to_owned();
        self.store
            .write(move |tx| insert(tx, &username, role, &hash))
            .await?
    }

    /// Fetch a user by id.
    ///
    /// # Errors
    /// [`UserError::NotFound`] or a store failure.
    pub async fn get(&self, id: UserId) -> Result<User, UserError> {
        self.store
            .read(move |c| {
                Ok(c.query_row(
                    &format!("SELECT {COLUMNS} FROM users WHERE id = ?1"),
                    [id.0],
                    row_to_user,
                )
                .optional()?)
            })
            .await?
            .ok_or(UserError::NotFound)
    }

    /// All users ordered by username.
    ///
    /// # Errors
    /// A store failure.
    pub async fn list(&self) -> Result<Vec<User>, UserError> {
        Ok(self
            .store
            .read(|c| {
                let mut stmt = c.prepare(&format!(
                    "SELECT {COLUMNS} FROM users ORDER BY username COLLATE NOCASE"
                ))?;
                Ok(stmt.query_map([], row_to_user)?.collect::<Result<_, _>>()?)
            })
            .await?)
    }

    /// Change a user's role. The last admin cannot be demoted.
    ///
    /// # Errors
    /// [`UserError::NotFound`], [`UserError::LastAdmin`], or a store failure.
    pub async fn update_role(&self, id: UserId, role: Role) -> Result<User, UserError> {
        self.store
            .write(move |tx| {
                let Some(user) = find(tx, id)? else {
                    return Ok(Err(UserError::NotFound));
                };
                if user.role == Role::Admin
                    && role != Role::Admin
                    && admin_count_excluding(tx, id)? == 0
                {
                    return Ok(Err(UserError::LastAdmin));
                }
                tx.execute(
                    "UPDATE users SET role = ?1, updated_at = unixepoch() WHERE id = ?2",
                    params![role_str(role), id.0],
                )?;
                Ok(Ok(User { role, ..user }))
            })
            .await?
    }

    /// Replace a user's password.
    ///
    /// # Errors
    /// [`UserError::Empty`], [`UserError::NotFound`], or a store failure.
    pub async fn set_password(&self, id: UserId, password: &str) -> Result<(), UserError> {
        check_input("x", password)?;
        let hash = hash_off_thread(password).await?;
        self.store
            .write(move |tx| {
                let n = tx.execute(
                    "UPDATE users SET password_hash = ?1, updated_at = unixepoch() WHERE id = ?2",
                    params![hash, id.0],
                )?;
                Ok(if n == 0 {
                    Err(UserError::NotFound)
                } else {
                    Ok(())
                })
            })
            .await?
    }

    /// Delete a user. The last admin cannot be deleted.
    ///
    /// # Errors
    /// [`UserError::NotFound`], [`UserError::LastAdmin`], or a store failure.
    pub async fn delete(&self, id: UserId) -> Result<(), UserError> {
        self.store
            .write(move |tx| {
                let Some(user) = find(tx, id)? else {
                    return Ok(Err(UserError::NotFound));
                };
                if user.role == Role::Admin && admin_count_excluding(tx, id)? == 0 {
                    return Ok(Err(UserError::LastAdmin));
                }
                tx.execute("DELETE FROM users WHERE id = ?1", [id.0])?;
                Ok(Ok(()))
            })
            .await?
    }

    /// Check a username and password. Unknown users and wrong passwords are
    /// indistinguishable (both [`UserError::InvalidCredentials`], with a hash
    /// computed either way to even out timing).
    ///
    /// # Errors
    /// [`UserError::InvalidCredentials`] or a store failure.
    pub async fn verify_password(&self, username: &str, password: &str) -> Result<User, UserError> {
        let name = username.trim().to_owned();
        let row = self
            .store
            .read(move |c| {
                Ok(c.query_row(
                    &format!("SELECT {COLUMNS}, password_hash FROM users WHERE username = ?1"),
                    [name],
                    |r| Ok((row_to_user(r)?, r.get::<_, String>(4)?)),
                )
                .optional()?)
            })
            .await?;
        let password = password.to_owned();
        let (user, ok) = blocking(move || match row {
            Some((user, phc)) => {
                let ok = password::verify(&password, &phc);
                (Some(user), ok)
            }
            None => {
                let _ = password::hash(&password);
                (None, false)
            }
        })
        .await?;
        match (user, ok) {
            (Some(user), true) => Ok(user),
            _ => Err(UserError::InvalidCredentials),
        }
    }

    /// Number of users.
    ///
    /// # Errors
    /// A store failure.
    pub async fn count(&self) -> Result<i64, UserError> {
        Ok(self
            .store
            .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?))
            .await?)
    }

    /// If there are no users, issue a one-time bootstrap code (valid 1 hour),
    /// print it once to stderr and return its handle. Returns `None` otherwise.
    ///
    /// # Errors
    /// A store failure.
    pub async fn start_bootstrap(&self) -> Result<Option<BootstrapCode>, UserError> {
        if self.count().await? > 0 {
            return Ok(None);
        }
        let (handle, code) = BootstrapCode::generate(bootstrap::TTL);
        eprintln!(
            "dnsy: no users exist. One-time bootstrap code (valid 1 hour, shown once): {code}"
        );
        Ok(Some(handle))
    }

    /// Create the first admin with a valid bootstrap code. The code is consumed
    /// on success and cannot be reused.
    ///
    /// # Errors
    /// [`UserError::InvalidBootstrapCode`] when the code is wrong, expired or used,
    /// or users already exist; plus the errors of [`UserService::create`].
    pub async fn bootstrap_admin(
        &self,
        bootstrap: &BootstrapCode,
        code: &str,
        username: &str,
        password: &str,
    ) -> Result<User, UserError> {
        if !bootstrap.is_valid(code) {
            return Err(UserError::InvalidBootstrapCode);
        }
        check_input(username, password)?;
        let hash = hash_off_thread(password).await?;
        let username = username.trim().to_owned();
        let user = self
            .store
            .write(move |tx| {
                let users: i64 = tx.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
                if users > 0 {
                    return Ok(Err(UserError::InvalidBootstrapCode));
                }
                insert(tx, &username, Role::Admin, &hash)
            })
            .await??;
        bootstrap.consume();
        Ok(user)
    }
}

async fn hash_off_thread(password: &str) -> Result<String, UserError> {
    let password = password.to_owned();
    blocking(move || password::hash(&password)).await?
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    async fn svc() -> (UserService, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("t.db")).unwrap();
        (UserService::new(store), dir)
    }

    #[tokio::test]
    async fn password_verify_roundtrip() {
        let (s, _d) = svc().await;
        let u = s
            .create("alice", "correct horse", Role::Viewer)
            .await
            .unwrap();
        assert_eq!(
            s.verify_password("alice", "correct horse").await.unwrap(),
            u
        );
        assert_eq!(
            s.verify_password("ALICE", "correct horse").await.unwrap(),
            u
        );
        assert!(matches!(
            s.verify_password("alice", "wrong").await,
            Err(UserError::InvalidCredentials)
        ));
        assert!(matches!(
            s.verify_password("nobody", "x").await,
            Err(UserError::InvalidCredentials)
        ));
        s.set_password(u.id, "new secret").await.unwrap();
        assert!(s.verify_password("alice", "correct horse").await.is_err());
        s.verify_password("alice", "new secret").await.unwrap();
    }

    #[tokio::test]
    async fn stored_hash_is_argon2id_owasp() {
        let (s, _d) = svc().await;
        let u = s.create("alice", "pw", Role::Admin).await.unwrap();
        let phc: String = s
            .store
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT password_hash FROM users WHERE id = ?1",
                    [u.id.0],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{phc}");
    }

    #[tokio::test]
    async fn duplicate_username_rejected() {
        let (s, _d) = svc().await;
        s.create("Alice", "pw", Role::Viewer).await.unwrap();
        assert!(matches!(
            s.create("aLiCe", "pw", Role::Admin).await,
            Err(UserError::DuplicateUsername)
        ));
        assert!(matches!(
            s.create(" ", "pw", Role::Admin).await,
            Err(UserError::Empty)
        ));
        assert!(matches!(
            s.create("bob", "", Role::Admin).await,
            Err(UserError::Empty)
        ));
        assert_eq!(s.list().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn last_admin_protected() {
        let (s, _d) = svc().await;
        let a = s.create("a", "pw", Role::Admin).await.unwrap();
        assert!(matches!(s.delete(a.id).await, Err(UserError::LastAdmin)));
        assert!(matches!(
            s.update_role(a.id, Role::Viewer).await,
            Err(UserError::LastAdmin)
        ));
        let b = s.create("b", "pw", Role::Admin).await.unwrap();
        assert_eq!(
            s.update_role(a.id, Role::Operator).await.unwrap().role,
            Role::Operator
        );
        assert!(matches!(s.delete(b.id).await, Err(UserError::LastAdmin)));
        s.delete(a.id).await.unwrap();
        assert!(matches!(s.get(a.id).await, Err(UserError::NotFound)));
        assert!(matches!(s.delete(a.id).await, Err(UserError::NotFound)));
        assert!(matches!(
            s.update_role(a.id, Role::Admin).await,
            Err(UserError::NotFound)
        ));
        assert!(matches!(
            s.set_password(a.id, "x").await,
            Err(UserError::NotFound)
        ));
    }

    #[tokio::test]
    async fn bootstrap_code_single_use_and_expires() {
        let (s, _d) = svc().await;
        let (h, code) = BootstrapCode::generate(bootstrap::TTL);
        assert!(matches!(
            s.bootstrap_admin(&h, "nope", "root", "pw").await,
            Err(UserError::InvalidBootstrapCode)
        ));
        let admin = s.bootstrap_admin(&h, &code, "root", "pw").await.unwrap();
        assert_eq!(admin.role, Role::Admin);
        assert!(matches!(
            s.bootstrap_admin(&h, &code, "root2", "pw").await,
            Err(UserError::InvalidBootstrapCode)
        ));
        assert_eq!(s.count().await.unwrap(), 1);

        let (s2, _d2) = svc().await;
        let (h2, code2) = BootstrapCode::generate(Duration::ZERO);
        assert!(matches!(
            s2.bootstrap_admin(&h2, &code2, "root", "pw").await,
            Err(UserError::InvalidBootstrapCode)
        ));
        assert_eq!(s2.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn bootstrap_only_without_users() {
        let (s, _d) = svc().await;
        let h = s.start_bootstrap().await.unwrap().expect("code issued");
        let _ = h;
        s.create("a", "pw", Role::Admin).await.unwrap();
        assert!(s.start_bootstrap().await.unwrap().is_none());
        let (h, code) = BootstrapCode::generate(bootstrap::TTL);
        assert!(matches!(
            s.bootstrap_admin(&h, &code, "b", "pw").await,
            Err(UserError::InvalidBootstrapCode)
        ));
        assert_eq!(s.list().await.unwrap().len(), 1);
    }
}
