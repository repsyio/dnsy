//! Persistence of list sources and custom rules (`blocklists`, `custom_rules`).

use dnsy_core::{Clock, SystemClock};
use dnsy_store::{Store, StoreError};
use rusqlite::{ErrorCode, Row, params};

use crate::fetch::Location;
use crate::parse::ListFormat;
use crate::rules::FilterError;

/// A persisted list source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListSource {
    pub id: i64,
    pub name: String,
    /// An http(s) URL or a file path.
    pub location: String,
    pub format: ListFormat,
    pub enabled: bool,
    pub interval_secs: u64,
    /// Allow a URL source to resolve to loopback, private or link-local addresses.
    pub allow_private: bool,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// Unix seconds of the last attempt.
    pub last_fetched: Option<i64>,
    /// `ok`, `not modified` or `error: ...`.
    pub last_status: Option<String>,
    /// Block plus allow entries read at the last successful load.
    pub entries: u64,
}

/// A source to add.
#[derive(Debug, Clone)]
pub struct NewSource {
    pub name: String,
    pub location: String,
    pub format: ListFormat,
    pub enabled: bool,
    pub interval_secs: u64,
    pub allow_private: bool,
}

/// The outcome of one refresh attempt, as stored.
#[derive(Debug, Clone)]
pub struct FetchRecord {
    pub at: i64,
    pub status: String,
    /// Validators and entry count, set only when a new body was loaded.
    pub loaded: Option<LoadedMeta>,
}

#[derive(Debug, Clone)]
pub struct LoadedMeta {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub entries: u64,
}

/// A stored custom rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomRule {
    pub id: i64,
    pub kind: RuleKind,
    pub domain: String,
}

/// A custom rule kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    Block,
    Allow,
}

impl RuleKind {
    fn as_str(self) -> &'static str {
        match self {
            RuleKind::Block => "block",
            RuleKind::Allow => "allow",
        }
    }
}

fn format_str(f: ListFormat) -> &'static str {
    match f {
        ListFormat::Auto => "auto",
        ListFormat::Hosts => "hosts",
        ListFormat::Domains => "domains",
        ListFormat::Adblock => "adblock",
    }
}

fn format_parse(s: &str) -> Option<ListFormat> {
    Some(match s {
        "auto" => ListFormat::Auto,
        "hosts" => ListFormat::Hosts,
        "domains" => ListFormat::Domains,
        "adblock" => ListFormat::Adblock,
        _ => return None,
    })
}

const COLUMNS: &str = "id, name, location, format, enabled, interval_secs, allow_private, etag, \
                       last_modified, last_fetched, last_status, entries";

fn row(r: &Row<'_>) -> rusqlite::Result<(ListSource, String)> {
    let format: String = r.get(3)?;
    Ok((
        ListSource {
            id: r.get(0)?,
            name: r.get(1)?,
            location: r.get(2)?,
            format: ListFormat::Auto,
            enabled: r.get(4)?,
            interval_secs: r.get::<_, i64>(5)?.unsigned_abs(),
            allow_private: r.get(6)?,
            etag: r.get(7)?,
            last_modified: r.get(8)?,
            last_fetched: r.get(9)?,
            last_status: r.get(10)?,
            entries: r.get::<_, i64>(11)?.unsigned_abs(),
        },
        format,
    ))
}

fn finish(rows: Vec<(ListSource, String)>) -> Result<Vec<ListSource>, FilterError> {
    rows.into_iter()
        .map(|(mut s, f)| {
            s.format = format_parse(&f).ok_or(FilterError::Corrupt)?;
            Ok(s)
        })
        .collect()
}

fn constraint(e: StoreError) -> FilterError {
    match e {
        StoreError::Sqlite(rusqlite::Error::SqliteFailure(f, _))
            if f.code == ErrorCode::ConstraintViolation =>
        {
            FilterError::Duplicate
        }
        other => other.into(),
    }
}

/// SQLite-backed list sources and custom rules.
#[derive(Clone)]
pub struct SourceStore {
    store: Store,
}

impl SourceStore {
    #[must_use]
    pub fn new(store: Store) -> SourceStore {
        SourceStore { store }
    }

    /// Adds a source and returns its id.
    ///
    /// # Errors
    /// [`FilterError::Invalid`] for an unsupported location or an out-of-range name or
    /// interval; [`FilterError::Duplicate`] if the name or location exists.
    pub async fn add(&self, new: NewSource) -> Result<i64, FilterError> {
        Location::parse(&new.location).map_err(|e| FilterError::Invalid(e.to_string()))?;
        if new.name.is_empty() || new.name.chars().count() > 128 || new.interval_secs == 0 {
            return Err(FilterError::Invalid("name or interval out of range".into()));
        }
        let interval = i64::try_from(new.interval_secs)
            .map_err(|_| FilterError::Invalid("interval too large".into()))?;
        let now = SystemClock.unix_secs();
        self.store
            .write(move |tx| {
                tx.execute(
                    "INSERT INTO blocklists
                     (name, location, format, enabled, interval_secs, allow_private, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        new.name,
                        new.location,
                        format_str(new.format),
                        new.enabled,
                        interval,
                        new.allow_private,
                        now
                    ],
                )?;
                Ok(tx.last_insert_rowid())
            })
            .await
            .map_err(constraint)
    }

    /// All sources, oldest first.
    ///
    /// # Errors
    /// Store failure or a corrupt row.
    pub async fn list(&self) -> Result<Vec<ListSource>, FilterError> {
        let rows = self
            .store
            .read(|c| {
                let mut stmt =
                    c.prepare(&format!("SELECT {COLUMNS} FROM blocklists ORDER BY id"))?;
                let rows = stmt.query_map([], row)?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .await?;
        finish(rows)
    }

    /// Enables or disables a source.
    ///
    /// # Errors
    /// [`FilterError::NotFound`] if no such source.
    pub async fn set_enabled(&self, id: i64, enabled: bool) -> Result<(), FilterError> {
        let n = self
            .store
            .write(move |tx| {
                Ok(tx.execute(
                    "UPDATE blocklists SET enabled = ?2 WHERE id = ?1",
                    params![id, enabled],
                )?)
            })
            .await?;
        if n == 0 {
            Err(FilterError::NotFound)
        } else {
            Ok(())
        }
    }

    /// Deletes a source.
    ///
    /// # Errors
    /// [`FilterError::NotFound`] if no such source.
    pub async fn delete(&self, id: i64) -> Result<(), FilterError> {
        let n = self
            .store
            .write(move |tx| Ok(tx.execute("DELETE FROM blocklists WHERE id = ?1", [id])?))
            .await?;
        if n == 0 {
            Err(FilterError::NotFound)
        } else {
            Ok(())
        }
    }

    /// Stores the outcome of a refresh attempt.
    ///
    /// # Errors
    /// Store failure.
    pub async fn record(&self, id: i64, rec: FetchRecord) -> Result<(), FilterError> {
        self.store
            .write(move |tx| {
                tx.execute(
                    "UPDATE blocklists SET last_fetched = ?2, last_status = ?3 WHERE id = ?1",
                    params![id, rec.at, rec.status],
                )?;
                if let Some(m) = rec.loaded {
                    tx.execute(
                        "UPDATE blocklists SET etag = ?2, last_modified = ?3, entries = ?4
                         WHERE id = ?1",
                        params![
                            id,
                            m.etag,
                            m.last_modified,
                            i64::try_from(m.entries).unwrap_or(i64::MAX)
                        ],
                    )?;
                }
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Adds the first-start `seed` locations when no source exists yet.
    ///
    /// # Errors
    /// An invalid location or store failure.
    pub async fn seed(&self, locations: &[String], interval_secs: u64) -> Result<(), FilterError> {
        if !self.list().await?.is_empty() {
            return Ok(());
        }
        for location in locations {
            self.add(NewSource {
                name: location.chars().take(128).collect(),
                location: location.clone(),
                format: ListFormat::Auto,
                enabled: true,
                interval_secs,
                allow_private: false,
            })
            .await?;
        }
        Ok(())
    }

    /// Adds a custom rule (suffix match).
    ///
    /// # Errors
    /// [`FilterError::Duplicate`] if the rule exists.
    pub async fn add_custom_rule(&self, kind: RuleKind, domain: &str) -> Result<i64, FilterError> {
        let domain = domain.to_owned();
        let now = SystemClock.unix_secs();
        self.store
            .write(move |tx| {
                tx.execute(
                    "INSERT INTO custom_rules (kind, domain, created_at) VALUES (?1, ?2, ?3)",
                    params![kind.as_str(), domain, now],
                )?;
                Ok(tx.last_insert_rowid())
            })
            .await
            .map_err(constraint)
    }

    /// Custom rules with their ids, oldest first.
    ///
    /// # Errors
    /// Store failure or a corrupt row.
    pub async fn custom_rules_with_ids(&self) -> Result<Vec<CustomRule>, FilterError> {
        let rows: Vec<(i64, String, String)> = self
            .store
            .read(|c| {
                let mut stmt =
                    c.prepare("SELECT id, kind, domain FROM custom_rules ORDER BY id")?;
                let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
                Ok(rows.collect::<Result<_, _>>()?)
            })
            .await?;
        rows.into_iter()
            .map(|(id, k, domain)| {
                let kind = match k.as_str() {
                    "block" => RuleKind::Block,
                    "allow" => RuleKind::Allow,
                    _ => return Err(FilterError::Corrupt),
                };
                Ok(CustomRule { id, kind, domain })
            })
            .collect()
    }

    /// Delete a custom rule.
    ///
    /// # Errors
    /// [`FilterError::NotFound`] if no such rule.
    pub async fn delete_custom_rule(&self, id: i64) -> Result<(), FilterError> {
        let n = self
            .store
            .write(move |tx| Ok(tx.execute("DELETE FROM custom_rules WHERE id = ?1", [id])?))
            .await?;
        if n == 0 {
            Err(FilterError::NotFound)
        } else {
            Ok(())
        }
    }

    /// All custom rules, oldest first.
    ///
    /// # Errors
    /// Store failure or a corrupt row.
    pub async fn custom_rules(&self) -> Result<Vec<(RuleKind, String)>, FilterError> {
        let rows: Vec<(String, String)> = self
            .store
            .read(|c| {
                let mut stmt = c.prepare("SELECT kind, domain FROM custom_rules ORDER BY id")?;
                let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
                Ok(rows.collect::<Result<_, _>>()?)
            })
            .await?;
        rows.into_iter()
            .map(|(k, d)| match k.as_str() {
                "block" => Ok((RuleKind::Block, d)),
                "allow" => Ok((RuleKind::Allow, d)),
                _ => Err(FilterError::Corrupt),
            })
            .collect()
    }
}
