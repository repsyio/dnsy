use dnsy_core::{Clock, SystemClock};
use dnsy_store::{Store, StoreError};
use ipnet::IpNet;
use rusqlite::{ErrorCode, params};

/// What to do with a request from a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AclAction {
    Allow,
    /// Answer REFUSED.
    Refuse,
    /// Send nothing.
    Drop,
}

impl AclAction {
    /// Higher is stricter; used to break ties between equally specific rules.
    #[must_use]
    pub fn strictness(self) -> u8 {
        match self {
            AclAction::Allow => 0,
            AclAction::Refuse => 1,
            AclAction::Drop => 2,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            AclAction::Allow => "allow",
            AclAction::Refuse => "refuse",
            AclAction::Drop => "drop",
        }
    }

    pub(crate) fn parse(s: &str) -> Option<AclAction> {
        match s {
            "allow" => Some(AclAction::Allow),
            "refuse" => Some(AclAction::Refuse),
            "drop" => Some(AclAction::Drop),
            _ => None,
        }
    }
}

/// What a rule matches on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclMatcher {
    /// Client address inside the network (host bits are ignored).
    Cidr(IpNet),
    /// mTLS client certificate by SHA-256 fingerprint.
    ClientCert([u8; 32]),
}

/// Failure of a rule persistence operation.
#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    #[error("an identical rule already exists")]
    Duplicate,
    #[error("rule not found")]
    NotFound,
    #[error("invalid list source: {0}")]
    Invalid(String),
    #[error("stored rule is corrupt")]
    Corrupt,
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// A persisted ACL rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclRule {
    pub id: i64,
    pub matcher: AclMatcher,
    pub action: AclAction,
    pub comment: String,
}

/// SQLite-backed ACL rules and rate-limit setting (`acl_rules`, `rate_limits`).
#[derive(Clone)]
pub struct RuleStore {
    store: Store,
}

impl RuleStore {
    #[must_use]
    pub fn new(store: Store) -> RuleStore {
        RuleStore { store }
    }

    /// Add a rule and return its id.
    ///
    /// # Errors
    /// [`FilterError::Duplicate`] if the same network or certificate already has a rule.
    pub async fn add(
        &self,
        matcher: AclMatcher,
        action: AclAction,
        comment: &str,
    ) -> Result<i64, FilterError> {
        let comment = comment.to_owned();
        let now = SystemClock.unix_secs();
        let res = self
            .store
            .write(move |tx| {
                let (kind, cidr, cert): (&str, Option<String>, Option<Vec<u8>>) = match &matcher {
                    AclMatcher::Cidr(n) => ("cidr", Some(n.trunc().to_string()), None),
                    AclMatcher::ClientCert(fp) => ("cert", None, Some(fp.to_vec())),
                };
                tx.execute(
                    "INSERT INTO acl_rules (kind, cidr, cert_sha256, action, comment, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![kind, cidr, cert, action.as_str(), comment, now],
                )?;
                Ok(tx.last_insert_rowid())
            })
            .await;
        match res {
            Err(StoreError::Sqlite(rusqlite::Error::SqliteFailure(e, _)))
                if e.code == ErrorCode::ConstraintViolation =>
            {
                Err(FilterError::Duplicate)
            }
            other => Ok(other?),
        }
    }

    /// Delete a rule.
    ///
    /// # Errors
    /// [`FilterError::NotFound`] if no such rule.
    pub async fn delete(&self, id: i64) -> Result<(), FilterError> {
        let n = self
            .store
            .write(move |tx| Ok(tx.execute("DELETE FROM acl_rules WHERE id = ?1", [id])?))
            .await?;
        if n == 0 {
            Err(FilterError::NotFound)
        } else {
            Ok(())
        }
    }

    /// All rules, oldest first.
    ///
    /// # Errors
    /// Store failure or a corrupt row.
    pub async fn list(&self) -> Result<Vec<AclRule>, FilterError> {
        type Row = (i64, String, Option<String>, Option<Vec<u8>>, String, String);
        let rows: Vec<Row> = self
            .store
            .read(|c| {
                let mut stmt = c.prepare(
                    "SELECT id, kind, cidr, cert_sha256, action, comment FROM acl_rules ORDER BY id",
                )?;
                let rows = stmt.query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
                })?;
                Ok(rows.collect::<Result<_, _>>()?)
            })
            .await?;
        rows.into_iter()
            .map(|(id, kind, cidr, cert, action, comment)| {
                let matcher = match (kind.as_str(), cidr, cert) {
                    ("cidr", Some(c), None) => {
                        AclMatcher::Cidr(c.parse::<IpNet>().map_err(|_| FilterError::Corrupt)?)
                    }
                    ("cert", None, Some(c)) => {
                        AclMatcher::ClientCert(c.try_into().map_err(|_| FilterError::Corrupt)?)
                    }
                    _ => return Err(FilterError::Corrupt),
                };
                Ok(AclRule {
                    id,
                    matcher,
                    action: AclAction::parse(&action).ok_or(FilterError::Corrupt)?,
                    comment,
                })
            })
            .collect()
    }

    /// Persisted queries-per-second limit; `None` if never set.
    ///
    /// # Errors
    /// Store failure.
    pub async fn rate_limit_qps(&self) -> Result<Option<u32>, FilterError> {
        let v: Option<i64> = self
            .store
            .read(|c| {
                match c.query_row("SELECT qps FROM rate_limits WHERE id = 1", [], |r| r.get(0)) {
                    Ok(v) => Ok(Some(v)),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await?;
        Ok(v.map(|v| u32::try_from(v).unwrap_or(u32::MAX)))
    }

    /// Persist the queries-per-second limit (0 disables limiting).
    ///
    /// # Errors
    /// Store failure.
    pub async fn set_rate_limit_qps(&self, qps: u32) -> Result<(), FilterError> {
        let now = SystemClock.unix_secs();
        self.store
            .write(move |tx| {
                tx.execute(
                    "INSERT INTO rate_limits (id, qps, updated_at) VALUES (1, ?1, ?2)
                     ON CONFLICT(id) DO UPDATE SET qps = ?1, updated_at = ?2",
                    params![i64::from(qps), now],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Persisted response-IP networks (canonical text, one network per entry); `None` if never
    /// set through the API, in which case `[filter] response_ip_blocklist` applies.
    ///
    /// # Errors
    /// Store failure.
    pub async fn response_ip_cidrs(&self) -> Result<Option<Vec<String>>, FilterError> {
        let v: Option<String> = self
            .store
            .read(|c| {
                match c.query_row(
                    "SELECT cidrs FROM response_ip_policy WHERE id = 1",
                    [],
                    |r| r.get(0),
                ) {
                    Ok(v) => Ok(Some(v)),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await?;
        Ok(v.map(|v| v.lines().map(str::to_owned).collect()))
    }

    /// Replace the persisted response-IP networks (an empty list disables the policy).
    ///
    /// # Errors
    /// Store failure.
    pub async fn set_response_ip_cidrs(&self, cidrs: &[String]) -> Result<(), FilterError> {
        let now = SystemClock.unix_secs();
        let joined = cidrs.join("\n");
        self.store
            .write(move |tx| {
                tx.execute(
                    "INSERT INTO response_ip_policy (id, cidrs, updated_at) VALUES (1, ?1, ?2)
                     ON CONFLICT(id) DO UPDATE SET cidrs = ?1, updated_at = ?2",
                    params![joined, now],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_names_round_trip() {
        for a in [AclAction::Allow, AclAction::Refuse, AclAction::Drop] {
            assert_eq!(AclAction::parse(a.as_str()), Some(a));
        }
        assert_eq!(AclAction::parse("x"), None);
    }

    fn setup() -> (RuleStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("t.db")).unwrap();
        (RuleStore::new(store), dir)
    }

    #[tokio::test]
    async fn add_list_delete_round_trip() {
        let (rs, _d) = setup();
        let a = rs
            .add(
                AclMatcher::Cidr("10.0.0.7/8".parse().unwrap()),
                AclAction::Refuse,
                "lan",
            )
            .await
            .unwrap();
        let b = rs
            .add(AclMatcher::ClientCert([3; 32]), AclAction::Allow, "")
            .await
            .unwrap();
        let rules = rs.list().await.unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, a);
        assert_eq!(
            rules[0].matcher,
            AclMatcher::Cidr("10.0.0.0/8".parse().unwrap())
        );
        assert_eq!(rules[0].comment, "lan");
        assert_eq!(rules[1].matcher, AclMatcher::ClientCert([3; 32]));
        rs.delete(a).await.unwrap();
        assert_eq!(rs.list().await.unwrap()[0].id, b);
        assert!(matches!(rs.delete(a).await, Err(FilterError::NotFound)));
    }

    #[tokio::test]
    async fn duplicates_rejected() {
        let (rs, _d) = setup();
        let m = AclMatcher::Cidr("10.0.0.0/8".parse().unwrap());
        rs.add(m.clone(), AclAction::Drop, "").await.unwrap();
        assert!(matches!(
            rs.add(
                AclMatcher::Cidr("10.1.1.1/8".parse().unwrap()),
                AclAction::Allow,
                ""
            )
            .await,
            Err(FilterError::Duplicate)
        ));
        rs.add(AclMatcher::ClientCert([1; 32]), AclAction::Drop, "")
            .await
            .unwrap();
        assert!(matches!(
            rs.add(AclMatcher::ClientCert([1; 32]), AclAction::Allow, "")
                .await,
            Err(FilterError::Duplicate)
        ));
    }

    #[tokio::test]
    async fn rate_limit_setting_persists() {
        let (rs, _d) = setup();
        assert_eq!(rs.rate_limit_qps().await.unwrap(), None);
        rs.set_rate_limit_qps(50).await.unwrap();
        rs.set_rate_limit_qps(70).await.unwrap();
        assert_eq!(rs.rate_limit_qps().await.unwrap(), Some(70));
    }

    #[tokio::test]
    async fn response_ip_setting_persists() {
        let (rs, _d) = setup();
        assert_eq!(rs.response_ip_cidrs().await.unwrap(), None);
        rs.set_response_ip_cidrs(&["10.0.0.0/8".to_owned(), "fc00::/7".to_owned()])
            .await
            .unwrap();
        assert_eq!(
            rs.response_ip_cidrs().await.unwrap(),
            Some(vec!["10.0.0.0/8".to_owned(), "fc00::/7".to_owned()])
        );
        rs.set_response_ip_cidrs(&[]).await.unwrap();
        assert_eq!(rs.response_ip_cidrs().await.unwrap(), Some(vec![]));
    }

    #[tokio::test]
    async fn corrupt_rows_are_reported() {
        let (rs, _d) = setup();
        rs.store
            .write(|tx| {
                tx.execute(
                    "INSERT INTO acl_rules (kind, cidr, action, created_at) VALUES ('cidr', 'nope', 'allow', 0)",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(rs.list().await, Err(FilterError::Corrupt)));
    }
}
