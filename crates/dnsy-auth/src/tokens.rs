use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dnsy_core::{Clock, Principal, Role, Scope, SystemClock, TokenId, UserId};
use dnsy_store::Store;
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::AuthError;

const PREFIX: &str = "dnsy_";
/// `last_used_at` is refreshed at most this often.
const LAST_USED_GRANULARITY_SECS: i64 = 60;
const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Verifies a presented bearer token for a needed scope.
pub trait TokenVerifier: Send + Sync {
    fn verify(
        &self,
        presented: &str,
        needed: Scope,
    ) -> impl Future<Output = Result<Principal, AuthError>> + Send;
}

/// Token metadata. The secret is never part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenMeta {
    pub id: TokenId,
    pub user: UserId,
    pub name: String,
    pub scopes: Vec<Scope>,
    /// Unix seconds.
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub revoked: bool,
}

fn scope_str(s: Scope) -> &'static str {
    match s {
        Scope::DnsQuery => "dns:query",
        Scope::ApiRead => "api:read",
        Scope::ApiWrite => "api:write",
        Scope::Admin => "admin",
    }
}

fn parse_scopes(s: &str) -> Vec<Scope> {
    s.split(',')
        .filter_map(|p| match p {
            "dns:query" => Some(Scope::DnsQuery),
            "api:read" => Some(Scope::ApiRead),
            "api:write" => Some(Scope::ApiWrite),
            "admin" => Some(Scope::Admin),
            _ => None,
        })
        .collect()
}

fn parse_role(s: &str) -> Role {
    match s {
        "admin" => Role::Admin,
        "operator" => Role::Operator,
        _ => Role::Viewer,
    }
}

fn b32_encode(bytes: [u8; 8]) -> String {
    let mut v = u64::from_be_bytes(bytes);
    // 64 bits = 12 full groups of 5 bits + 4 bits, left-aligned in the last group.
    let mut out = String::with_capacity(13);
    out.push(char::from(B32[((v >> 59) & 31) as usize]));
    v <<= 5;
    for _ in 0..11 {
        out.push(char::from(B32[((v >> 59) & 31) as usize]));
        v <<= 5;
    }
    out.push(char::from(B32[((v >> 59) & 31) as usize]));
    out
}

fn b32_decode(s: &str) -> Option<[u8; 8]> {
    if s.len() != 13 {
        return None;
    }
    let mut v: u128 = 0;
    for c in s.bytes() {
        let idx = B32.iter().position(|&b| b == c)?;
        v = (v << 5) | idx as u128;
    }
    // 65 bits decoded, the last bit is padding and must be zero.
    if v & 1 != 0 {
        return None;
    }
    Some(u64::try_from(v >> 1).ok()?.to_be_bytes())
}

fn parse_token(presented: &str) -> Option<(i64, [u8; 32])> {
    let rest = presented.strip_prefix(PREFIX)?;
    let (id, secret) = rest.split_once('_')?;
    let id = i64::from_be_bytes(b32_decode(id)?);
    let secret: [u8; 32] = URL_SAFE_NO_PAD.decode(secret).ok()?.try_into().ok()?;
    (id >= 0).then_some((id, secret))
}

type Row = (
    i64,
    Vec<u8>,
    String,
    String,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

/// A successful verification, reused until `ttl` passes or the store's auth epoch moves.
struct Cached {
    principal: Principal,
    scopes: Vec<Scope>,
    role: Role,
    expires_at: Option<i64>,
    inserted: Instant,
    epoch: u64,
}

impl Cached {
    fn usable(&self, at: Instant, ttl: Duration, epoch: u64, now: i64) -> bool {
        at < self.inserted + ttl && self.epoch == epoch && self.expires_at.is_none_or(|e| e > now)
    }
}

/// Verified-token cache, keyed by the SHA-256 of the presented string. Only successes are
/// stored; a full map is cleared rather than grown.
struct TokenCache {
    ttl: Duration,
    capacity: usize,
    entries: RwLock<HashMap<[u8; 32], Cached>>,
}

/// Issues, lists, revokes and verifies API tokens.
#[derive(Clone)]
pub struct TokenService {
    store: Store,
    cache: Option<Arc<TokenCache>>,
}

impl TokenService {
    #[must_use]
    pub fn new(store: Store) -> TokenService {
        TokenService { store, cache: None }
    }

    /// Cache successful verifications for `ttl`, holding at most `capacity` tokens (the map is
    /// cleared when full). Revocations, role changes, disabling and deleting through this
    /// process's `dnsy-auth` services invalidate the cache at once through the store's
    /// [`dnsy_store::Epoch`]; writes from another process (the `dnsy admin` CLI) are seen only
    /// when an entry expires, so within `ttl`. `last_used_at` is refreshed on cache misses only.
    #[must_use]
    pub fn with_cache(mut self, ttl: Duration, capacity: usize) -> TokenService {
        self.cache = Some(Arc::new(TokenCache {
            ttl,
            capacity,
            entries: RwLock::new(HashMap::new()),
        }));
        self
    }

    /// Create a token for `user`. The returned string is the only time the secret
    /// is available; only its SHA-256 is stored.
    ///
    /// # Errors
    /// [`AuthError::UserNotFound`], [`AuthError::ScopeNotAllowed`] when a scope is
    /// outside the owner's role, or a store failure.
    pub async fn create(
        &self,
        user: UserId,
        name: &str,
        scopes: &[Scope],
        expires_at: Option<i64>,
    ) -> Result<(String, TokenMeta), AuthError> {
        self.create_at(user, name, scopes, expires_at, SystemClock.unix_secs())
            .await
    }

    pub(crate) async fn create_at(
        &self,
        user: UserId,
        name: &str,
        scopes: &[Scope],
        expires_at: Option<i64>,
        now: i64,
    ) -> Result<(String, TokenMeta), AuthError> {
        let mut raw = [0u8; 8];
        rand::fill(&mut raw[..]);
        // 53 bits: the web UI reads ids as JSON numbers (f64) and must get them back exactly.
        raw[0] = 0;
        raw[1] &= 0x1f;
        let id = i64::from_be_bytes(raw);
        let mut secret = [0u8; 32];
        rand::fill(&mut secret[..]);
        let token = format!(
            "{PREFIX}{}_{}",
            b32_encode(raw),
            URL_SAFE_NO_PAD.encode(secret)
        );
        let hash = sha256(&secret);
        let scopes = scopes.to_vec();
        let name = name.trim().to_owned();
        let meta = TokenMeta {
            id: TokenId(id),
            user,
            name: name.clone(),
            scopes: scopes.clone(),
            created_at: now,
            expires_at,
            last_used_at: None,
            revoked: false,
        };
        let joined = scopes
            .iter()
            .map(|s| scope_str(*s))
            .collect::<Vec<_>>()
            .join(",");
        let res = self
            .store
            .write(move |tx| {
                let role: Option<String> = tx
                    .query_row("SELECT role FROM users WHERE id = ?1", [user.0], |r| r.get(0))
                    .optional()?;
                let Some(role) = role else {
                    return Ok(Err(AuthError::UserNotFound));
                };
                let role = parse_role(&role);
                if scopes.is_empty() || scopes.iter().any(|s| !role.allows(*s)) {
                    return Ok(Err(AuthError::ScopeNotAllowed));
                }
                tx.execute(
                    "INSERT INTO api_tokens (id, user_id, name, scopes, secret_sha256, created_at, expires_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![id, user.0, name, joined, hash, now, expires_at],
                )?;
                Ok(Ok(()))
            })
            .await?;
        self.store.epoch().bump();
        res?;
        Ok((token, meta))
    }

    /// All tokens of `user`, newest first.
    ///
    /// # Errors
    /// A store failure.
    pub async fn list(&self, user: UserId) -> Result<Vec<TokenMeta>, AuthError> {
        Ok(self
            .store
            .read(move |c| {
                let mut stmt = c.prepare(
                    "SELECT id, name, scopes, created_at, expires_at, last_used_at, revoked_at
                     FROM api_tokens WHERE user_id = ?1 ORDER BY created_at DESC, id DESC",
                )?;
                let rows = stmt.query_map([user.0], |r| {
                    Ok(TokenMeta {
                        id: TokenId(r.get(0)?),
                        user,
                        name: r.get(1)?,
                        scopes: parse_scopes(&r.get::<_, String>(2)?),
                        created_at: r.get(3)?,
                        expires_at: r.get(4)?,
                        last_used_at: r.get(5)?,
                        revoked: r.get::<_, Option<i64>>(6)?.is_some(),
                    })
                })?;
                Ok(rows.collect::<Result<_, _>>()?)
            })
            .await?)
    }

    /// Revoke a token. Revoking twice is fine.
    ///
    /// # Errors
    /// [`AuthError::TokenNotFound`] or a store failure.
    pub async fn revoke(&self, id: TokenId) -> Result<(), AuthError> {
        let now = SystemClock.unix_secs();
        let n = self
            .store
            .write(move |tx| {
                Ok(tx.execute(
                    "UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, ?2) WHERE id = ?1",
                    params![id.0, now],
                )?)
            })
            .await?;
        self.store.epoch().bump();
        if n == 0 {
            Err(AuthError::TokenNotFound)
        } else {
            Ok(())
        }
    }

    pub(crate) async fn verify_at(
        &self,
        presented: &str,
        needed: Scope,
        now: i64,
    ) -> Result<Principal, AuthError> {
        self.verify_cached_at(presented, needed, now, Instant::now())
            .await
    }

    /// [`Self::verify_at`] with the cache clock passed in (`at`), so tests control the TTL.
    async fn verify_cached_at(
        &self,
        presented: &str,
        needed: Scope,
        now: i64,
        at: Instant,
    ) -> Result<Principal, AuthError> {
        let Some(cache) = &self.cache else {
            return self.verify_db(presented, needed, now).await.map(|v| v.0);
        };
        let key: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        let epoch = self.store.epoch().current();
        let hit = {
            let entries = cache.entries.read().unwrap_or_else(PoisonError::into_inner);
            entries.get(&key).map(|c| {
                c.usable(at, cache.ttl, epoch, now).then(|| {
                    (
                        c.principal.clone(),
                        c.scopes.contains(&needed) && c.role.allows(needed),
                    )
                })
            })
        };
        match hit {
            Some(Some((principal, true))) => return Ok(principal),
            Some(Some((_, false))) => return Err(AuthError::MissingScope),
            Some(None) => {
                cache
                    .entries
                    .write()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&key);
            }
            None => {}
        }
        let (principal, cached) = self.verify_db(presented, needed, now).await?;
        let mut entries = cache
            .entries
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if entries.len() >= cache.capacity {
            entries.clear();
        }
        // The epoch read before the database lookup: a change committed meanwhile makes
        // this entry stale at once.
        entries.insert(
            key,
            Cached {
                inserted: at,
                epoch,
                ..cached
            },
        );
        Ok(principal)
    }

    /// The database path: one read, constant-time secret comparison, `last_used_at` refresh.
    async fn verify_db(
        &self,
        presented: &str,
        needed: Scope,
        now: i64,
    ) -> Result<(Principal, Cached), AuthError> {
        let (id, secret) = parse_token(presented).ok_or(AuthError::InvalidToken)?;
        let row: Option<Row> = self
            .store
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT t.user_id, t.secret_sha256, t.scopes, u.role, t.expires_at,
                            t.revoked_at, t.last_used_at, u.disabled_at
                     FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.id = ?1",
                    [id],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                            r.get(7)?,
                        ))
                    },
                )
                .optional()?)
            })
            .await?;
        let Some((user, stored, scopes, role, expires_at, revoked_at, last_used, disabled_at)) =
            row
        else {
            return Err(AuthError::InvalidToken);
        };
        if !bool::from(stored.as_slice().ct_eq(&sha256(&secret))) {
            return Err(AuthError::InvalidToken);
        }
        if revoked_at.is_some() || disabled_at.is_some() || expires_at.is_some_and(|e| e <= now) {
            return Err(AuthError::InvalidToken);
        }
        let scopes = parse_scopes(&scopes);
        let role = parse_role(&role);
        // Scope check also honours a role that was demoted after issuing.
        if !scopes.contains(&needed) || !role.allows(needed) {
            return Err(AuthError::MissingScope);
        }
        if last_used.is_none_or(|t| now - t >= LAST_USED_GRANULARITY_SECS) {
            self.store
                .write(move |tx| {
                    tx.execute(
                        "UPDATE api_tokens SET last_used_at = ?2 WHERE id = ?1",
                        params![id, now],
                    )?;
                    Ok(())
                })
                .await?;
        }
        let principal = Principal::Token {
            token: TokenId(id),
            user: UserId(user),
        };
        let cached = Cached {
            principal: principal.clone(),
            scopes,
            role,
            expires_at,
            inserted: Instant::now(),
            epoch: 0,
        };
        Ok((principal, cached))
    }
}

impl TokenVerifier for TokenService {
    async fn verify(&self, presented: &str, needed: Scope) -> Result<Principal, AuthError> {
        self.verify_at(presented, needed, SystemClock.unix_secs())
            .await
    }
}

#[cfg(test)]
mod tests {
    use dnsy_core::Role;

    use super::*;
    use crate::UserService;

    async fn setup(role: Role) -> (TokenService, UserId, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("t.db")).unwrap();
        let user = UserService::new(store.clone())
            .create("alice", "pw", role)
            .await
            .unwrap();
        (TokenService::new(store), user.id, dir)
    }

    #[test]
    fn base32_roundtrip_and_shape() {
        for raw in [[0u8; 8], [0x7f; 8], [1, 2, 3, 4, 5, 6, 7, 8]] {
            let s = b32_encode(raw);
            assert_eq!(s.len(), 13);
            assert_eq!(b32_decode(&s), Some(raw));
        }
        assert_eq!(b32_decode("short"), None);
        assert_eq!(b32_decode("AAAAAAAAAAAA!"), None);
    }

    /// The web UI parses ids as JSON numbers (f64): ids above 2^53 lose precision there and
    /// `DELETE /tokens/{id}` then answers 404 for a token the list just showed.
    #[tokio::test]
    async fn token_ids_survive_a_javascript_number() {
        let (svc, user, _d) = setup(Role::Operator).await;
        for i in 0..20 {
            let (_, meta) = svc
                .create(user, &format!("t{i}"), &[Scope::ApiRead], None)
                .await
                .unwrap();
            assert!(
                meta.id.0 > 0 && meta.id.0 < (1 << 53),
                "id {} too large",
                meta.id.0
            );
        }
    }

    #[tokio::test]
    async fn token_shown_once_verifies() {
        let (svc, user, _d) = setup(Role::Operator).await;
        let (token, meta) = svc
            .create(user, "ci", &[Scope::ApiRead, Scope::DnsQuery], None)
            .await
            .unwrap();
        assert!(token.starts_with("dnsy_"));
        assert_eq!(token.split('_').nth(1).unwrap().len(), 13);
        let p = svc.verify(&token, Scope::ApiRead).await.unwrap();
        assert_eq!(
            p,
            Principal::Token {
                token: meta.id,
                user
            }
        );
        assert!(matches!(
            svc.verify(&token, Scope::ApiWrite).await,
            Err(AuthError::MissingScope)
        ));
        // Neither list nor storage reveal the secret.
        let listed = svc.list(user).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "ci");
        assert!(!format!("{listed:?}").contains(&token[token.len() - 20..]));
        // Tampered secret and malformed tokens fail.
        let mid = token.len() - 10;
        let flipped = if &token[mid..=mid] == "A" { "B" } else { "A" };
        let bad = format!("{}{flipped}{}", &token[..mid], &token[mid + 1..]);
        assert!(matches!(
            svc.verify(&bad, Scope::ApiRead).await,
            Err(AuthError::InvalidToken)
        ));
        assert!(matches!(
            svc.verify("nope", Scope::ApiRead).await,
            Err(AuthError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn revoked_token_rejected() {
        let (svc, user, _d) = setup(Role::Admin).await;
        let (token, meta) = svc.create(user, "t", &[Scope::Admin], None).await.unwrap();
        svc.verify(&token, Scope::Admin).await.unwrap();
        svc.revoke(meta.id).await.unwrap();
        assert!(matches!(
            svc.verify(&token, Scope::Admin).await,
            Err(AuthError::InvalidToken)
        ));
        assert!(svc.list(user).await.unwrap()[0].revoked);
        assert!(matches!(
            svc.revoke(TokenId(1)).await,
            Err(AuthError::TokenNotFound)
        ));
    }

    #[tokio::test]
    async fn expired_token_rejected() {
        let (svc, user, _d) = setup(Role::Admin).await;
        let (token, _) = svc
            .create_at(user, "t", &[Scope::ApiRead], Some(1_100), 1_000)
            .await
            .unwrap();
        svc.verify_at(&token, Scope::ApiRead, 1_099).await.unwrap();
        assert!(matches!(
            svc.verify_at(&token, Scope::ApiRead, 1_100).await,
            Err(AuthError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn scope_subset_enforced() {
        let (svc, user, _d) = setup(Role::Viewer).await;
        assert!(matches!(
            svc.create(user, "t", &[Scope::ApiRead, Scope::ApiWrite], None)
                .await,
            Err(AuthError::ScopeNotAllowed)
        ));
        assert!(matches!(
            svc.create(user, "t", &[], None).await,
            Err(AuthError::ScopeNotAllowed)
        ));
        assert!(matches!(
            svc.create(UserId(999), "t", &[Scope::ApiRead], None).await,
            Err(AuthError::UserNotFound)
        ));
        svc.create(user, "t", &[Scope::ApiRead], None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn last_used_updates_at_most_once_per_minute() {
        let (svc, user, _d) = setup(Role::Admin).await;
        let (token, _) = svc
            .create_at(user, "t", &[Scope::ApiRead], None, 100)
            .await
            .unwrap();
        let last = |svc: &TokenService| {
            let svc = svc.clone();
            async move { svc.list(user).await.unwrap()[0].last_used_at }
        };
        assert_eq!(last(&svc).await, None);
        svc.verify_at(&token, Scope::ApiRead, 1_000).await.unwrap();
        svc.verify_at(&token, Scope::ApiRead, 1_059).await.unwrap();
        assert_eq!(last(&svc).await, Some(1_000));
        svc.verify_at(&token, Scope::ApiRead, 1_060).await.unwrap();
        assert_eq!(last(&svc).await, Some(1_060));
    }

    #[tokio::test]
    async fn demoted_owner_loses_scope() {
        let (svc, user, _d) = setup(Role::Admin).await;
        let (token, _) = svc.create(user, "t", &[Scope::Admin], None).await.unwrap();
        let users = UserService::new(svc.store.clone());
        users.create("bob", "pw", Role::Admin).await.unwrap();
        users.update_role(user, Role::Viewer).await.unwrap();
        assert!(matches!(
            svc.verify(&token, Scope::Admin).await,
            Err(AuthError::MissingScope)
        ));
    }

    #[tokio::test]
    async fn tokens_of_a_disabled_owner_stop_working_until_enabled() {
        let (svc, user, _d) = setup(Role::Admin).await;
        let (token, _) = svc
            .create(user, "t", &[Scope::ApiRead], None)
            .await
            .unwrap();
        let users = UserService::new(svc.store.clone());
        users.create("bob", "pw", Role::Admin).await.unwrap();
        svc.verify(&token, Scope::ApiRead).await.unwrap();
        users.set_disabled(user, true).await.unwrap();
        assert!(matches!(
            svc.verify(&token, Scope::ApiRead).await,
            Err(AuthError::InvalidToken)
        ));
        users.set_disabled(user, false).await.unwrap();
        svc.verify(&token, Scope::ApiRead).await.unwrap();
    }

    const TTL: Duration = Duration::from_secs(5);

    async fn cached(role: Role, capacity: usize) -> (TokenService, UserId, tempfile::TempDir) {
        let (svc, user, dir) = setup(role).await;
        (svc.with_cache(TTL, capacity), user, dir)
    }

    fn entries(svc: &TokenService) -> usize {
        svc.cache.as_ref().unwrap().entries.read().unwrap().len()
    }

    #[tokio::test]
    async fn cached_token_survives_a_direct_db_revoke_until_ttl() {
        let (svc, user, _d) = cached(Role::Operator, 16).await;
        let (token, _) = svc
            .create_at(user, "t", &[Scope::DnsQuery], None, 900)
            .await
            .unwrap();
        let t0 = Instant::now();
        svc.verify_cached_at(&token, Scope::DnsQuery, 1_000, t0)
            .await
            .unwrap();
        // An out-of-process writer (the CLI) does not bump the in-process epoch.
        svc.store
            .write(|tx| Ok(tx.execute("UPDATE api_tokens SET revoked_at = 1", [])?))
            .await
            .unwrap();
        svc.verify_cached_at(&token, Scope::DnsQuery, 1_004, t0 + Duration::from_secs(4))
            .await
            .unwrap();
        assert!(matches!(
            svc.verify_cached_at(&token, Scope::DnsQuery, 1_005, t0 + TTL)
                .await,
            Err(AuthError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn revoke_invalidates_the_cache_immediately() {
        let (svc, user, _d) = cached(Role::Operator, 16).await;
        let (token, meta) = svc
            .create(user, "t", &[Scope::DnsQuery], None)
            .await
            .unwrap();
        let t0 = Instant::now();
        svc.verify_cached_at(&token, Scope::DnsQuery, 1_000, t0)
            .await
            .unwrap();
        svc.revoke(meta.id).await.unwrap();
        assert!(matches!(
            svc.verify_cached_at(&token, Scope::DnsQuery, 1_000, t0)
                .await,
            Err(AuthError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn role_change_disable_and_delete_invalidate_immediately() {
        let (svc, user, _d) = cached(Role::Admin, 16).await;
        let users = UserService::new(svc.store.clone());
        users.create("bob", "pw", Role::Admin).await.unwrap();
        let (token, _) = svc
            .create(user, "t", &[Scope::ApiWrite], None)
            .await
            .unwrap();
        let t0 = Instant::now();
        let check = |svc: &TokenService| {
            let (svc, token) = (svc.clone(), token.clone());
            async move {
                svc.verify_cached_at(&token, Scope::ApiWrite, 1_000, t0)
                    .await
            }
        };
        check(&svc).await.unwrap();
        users.update_role(user, Role::Viewer).await.unwrap();
        assert!(matches!(check(&svc).await, Err(AuthError::MissingScope)));
        users.update_role(user, Role::Operator).await.unwrap();
        check(&svc).await.unwrap();
        users.set_disabled(user, true).await.unwrap();
        assert!(matches!(check(&svc).await, Err(AuthError::InvalidToken)));
        users.set_disabled(user, false).await.unwrap();
        check(&svc).await.unwrap();
        users.delete(user).await.unwrap();
        assert!(matches!(check(&svc).await, Err(AuthError::InvalidToken)));
    }

    #[tokio::test]
    async fn cached_entry_honours_expires_at() {
        let (svc, user, _d) = cached(Role::Operator, 16).await;
        let (token, _) = svc
            .create_at(user, "t", &[Scope::DnsQuery], Some(1_100), 1_000)
            .await
            .unwrap();
        let t0 = Instant::now();
        svc.verify_cached_at(&token, Scope::DnsQuery, 1_099, t0)
            .await
            .unwrap();
        assert_eq!(entries(&svc), 1);
        assert!(matches!(
            svc.verify_cached_at(&token, Scope::DnsQuery, 1_100, t0)
                .await,
            Err(AuthError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn cached_hit_still_checks_the_needed_scope() {
        let (svc, user, _d) = cached(Role::Operator, 16).await;
        let (token, _) = svc
            .create(user, "t", &[Scope::DnsQuery], None)
            .await
            .unwrap();
        let t0 = Instant::now();
        svc.verify_cached_at(&token, Scope::DnsQuery, 1_000, t0)
            .await
            .unwrap();
        assert!(matches!(
            svc.verify_cached_at(&token, Scope::ApiRead, 1_000, t0)
                .await,
            Err(AuthError::MissingScope)
        ));
    }

    #[tokio::test]
    async fn rejected_tokens_are_never_cached() {
        let (svc, user, _d) = cached(Role::Operator, 16).await;
        let (token, _) = svc
            .create(user, "t", &[Scope::DnsQuery], None)
            .await
            .unwrap();
        let mid = token.len() - 10;
        let flipped = if &token[mid..=mid] == "A" { "B" } else { "A" };
        let bad = format!("{}{flipped}{}", &token[..mid], &token[mid + 1..]);
        let t0 = Instant::now();
        for _ in 0..2 {
            assert!(matches!(
                svc.verify_cached_at(&bad, Scope::DnsQuery, 1_000, t0).await,
                Err(AuthError::InvalidToken)
            ));
        }
        assert!(matches!(
            svc.verify_cached_at(&token, Scope::ApiRead, 1_000, t0)
                .await,
            Err(AuthError::MissingScope)
        ));
        assert_eq!(entries(&svc), 0);
        svc.verify_cached_at(&token, Scope::DnsQuery, 1_000, t0)
            .await
            .unwrap();
        assert_eq!(entries(&svc), 1);
    }

    #[tokio::test]
    async fn cache_capacity_clears_not_grows() {
        let (svc, user, _d) = cached(Role::Operator, 2).await;
        let mut tokens = Vec::new();
        for i in 0..3 {
            let (token, _) = svc
                .create(user, &format!("t{i}"), &[Scope::DnsQuery], None)
                .await
                .unwrap();
            tokens.push(token);
        }
        let t0 = Instant::now();
        for token in &tokens {
            svc.verify_cached_at(token, Scope::DnsQuery, 1_000, t0)
                .await
                .unwrap();
            assert!(entries(&svc) <= 2);
        }
        for token in &tokens {
            svc.verify_cached_at(token, Scope::DnsQuery, 1_000, t0)
                .await
                .unwrap();
            assert!(entries(&svc) <= 2);
        }
    }

    #[tokio::test]
    async fn last_used_refresh_still_happens_through_the_cache() {
        let (svc, user, _d) = cached(Role::Operator, 16).await;
        let (token, _) = svc
            .create_at(user, "t", &[Scope::DnsQuery], None, 100)
            .await
            .unwrap();
        let last = |svc: &TokenService| {
            let svc = svc.clone();
            async move { svc.list(user).await.unwrap()[0].last_used_at }
        };
        let t0 = Instant::now();
        svc.verify_cached_at(&token, Scope::DnsQuery, 1_000, t0)
            .await
            .unwrap();
        svc.verify_cached_at(&token, Scope::DnsQuery, 1_003, t0 + Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(last(&svc).await, Some(1_000));
        svc.verify_cached_at(&token, Scope::DnsQuery, 1_065, t0 + Duration::from_secs(65))
            .await
            .unwrap();
        assert_eq!(last(&svc).await, Some(1_065));
    }

    #[test]
    fn constant_time_compare_used() {
        let src = include_str!("tokens.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        assert!(prod.contains(".ct_eq("));
        assert!(!prod.contains("stored == ") && !prod.contains("stored.as_slice() == "));
    }
}
