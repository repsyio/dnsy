use std::collections::BTreeMap;
use std::fmt::Write as _;

use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

use crate::StoreError;

/// A numbered SQL migration embedded in the binary.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    pub version: u32,
    pub name: &'static str,
    pub sql: &'static str,
}

impl Migration {
    /// Lowercase hex SHA-256 of the SQL text.
    #[must_use]
    pub fn checksum(&self) -> String {
        let digest = Sha256::digest(self.sql.as_bytes());
        digest.iter().fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }
}

/// Every known migration. Stories add their pre-assigned
/// `migrations/NNNN_name.sql` here, e.g.
/// `Migration { version: 1, name: "users", sql: include_str!("../migrations/0001_users.sql") }`.
pub static MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "users",
        sql: include_str!("../migrations/0001_users.sql"),
    },
    Migration {
        version: 2,
        name: "tokens_sessions",
        sql: include_str!("../migrations/0002_tokens_sessions.sql"),
    },
    Migration {
        version: 3,
        name: "querylog_stats",
        sql: include_str!("../migrations/0003_querylog_stats.sql"),
    },
    Migration {
        version: 4,
        name: "acl",
        sql: include_str!("../migrations/0004_acl.sql"),
    },
    Migration {
        version: 5,
        name: "upstreams",
        sql: include_str!("../migrations/0005_upstreams.sql"),
    },
    Migration {
        version: 6,
        name: "dnssec_keys",
        sql: include_str!("../migrations/0006_dnssec_keys.sql"),
    },
    Migration {
        version: 7,
        name: "blocklists",
        sql: include_str!("../migrations/0007_blocklists.sql"),
    },
    Migration {
        version: 8,
        name: "client_certs",
        sql: include_str!("../migrations/0008_client_certs.sql"),
    },
    Migration {
        version: 9,
        name: "user_disabled",
        sql: include_str!("../migrations/0009_user_disabled.sql"),
    },
    Migration {
        version: 10,
        name: "querylog_client_index",
        sql: include_str!("../migrations/0010_querylog_client_index.sql"),
    },
    Migration {
        version: 11,
        name: "querylog_rare_index",
        sql: include_str!("../migrations/0011_querylog_rare_index.sql"),
    },
    Migration {
        version: 12,
        name: "stats_top_day",
        sql: include_str!("../migrations/0012_stats_top_day.sql"),
    },
    Migration {
        version: 13,
        name: "stats_day",
        sql: include_str!("../migrations/0013_stats_day.sql"),
    },
    Migration {
        version: 14,
        name: "client_certs_autoincrement",
        sql: include_str!("../migrations/0014_client_certs_autoincrement.sql"),
    },
];

/// Applied state of one known migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationStatus {
    pub version: u32,
    pub name: String,
    /// Unix seconds when applied; `None` if pending.
    pub applied_at: Option<i64>,
}

const CREATE_TABLE: &str = "CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    checksum   TEXT NOT NULL,
    applied_at INTEGER NOT NULL
)";

fn applied(conn: &Connection) -> Result<BTreeMap<u32, (String, String, i64)>, StoreError> {
    conn.execute_batch(CREATE_TABLE)?;
    let mut stmt =
        conn.prepare("SELECT version, name, checksum, applied_at FROM schema_migrations")?;
    let rows = stmt.query_map([], |r| {
        Ok((r.get::<_, u32>(0)?, (r.get(1)?, r.get(2)?, r.get(3)?)))
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Verify the database against `known`: every applied migration must be known and unedited.
fn verify(
    applied: &BTreeMap<u32, (String, String, i64)>,
    known: &[Migration],
) -> Result<(), StoreError> {
    for (version, (name, checksum, _)) in applied {
        let Some(m) = known.iter().find(|m| m.version == *version) else {
            return Err(StoreError::UnknownMigration {
                version: *version,
                name: name.clone(),
            });
        };
        if m.checksum() != *checksum {
            return Err(StoreError::ChecksumMismatch {
                version: *version,
                name: m.name.to_owned(),
            });
        }
    }
    Ok(())
}

/// Apply every migration in `known` missing from the database, in version order.
pub(crate) fn run(conn: &mut Connection, known: &[Migration]) -> Result<(), StoreError> {
    verify(&applied(conn)?, known)?;
    let done = applied(conn)?;
    let mut pending: Vec<&Migration> = known
        .iter()
        .filter(|m| !done.contains_key(&m.version))
        .collect();
    pending.sort_by_key(|m| m.version);
    for m in pending {
        if m.sql.contains("CREATE INDEX") {
            tracing::info!(
                "applying migration {:04}_{}, this can take a while on a large query log",
                m.version,
                m.name
            );
        }
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute_batch(m.sql)
            .map_err(|source| StoreError::Migration {
                version: m.version,
                name: m.name.to_owned(),
                source,
            })?;
        tx.execute(
            "INSERT INTO schema_migrations (version, name, checksum, applied_at)
             VALUES (?1, ?2, ?3, unixepoch())",
            params![m.version, m.name, m.checksum()],
        )?;
        tx.commit()?;
    }
    Ok(())
}

pub(crate) fn status(
    conn: &Connection,
    known: &[Migration],
) -> Result<Vec<MigrationStatus>, StoreError> {
    let done = applied(conn)?;
    let mut out: Vec<MigrationStatus> = known
        .iter()
        .map(|m| MigrationStatus {
            version: m.version,
            name: m.name.to_owned(),
            applied_at: done.get(&m.version).map(|d| d.2),
        })
        .collect();
    out.sort_by_key(|s| s.version);
    Ok(out)
}
