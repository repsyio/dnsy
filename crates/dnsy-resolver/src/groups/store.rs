//! Persistence of upstream groups (migration `0005`).

use dnsy_core::{Clock, SystemClock};
use std::net::SocketAddr;

use dnsy_store::{Store, StoreError};
use rusqlite::params;

use super::{GroupMember, GroupSpec, Strategy};
use crate::upstream::{Upstream, UpstreamTransport};

/// Name of the group seeded from `[resolver] upstreams`.
pub const DEFAULT_GROUP: &str = "default";

/// Why a group could not be stored or loaded.
#[derive(Debug, thiserror::Error)]
pub enum GroupStoreError {
    #[error("stored group data is corrupt")]
    Corrupt,
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Reads and writes groups in the `upstream_groups` and `upstreams` tables.
#[derive(Clone)]
pub struct GroupStore {
    store: Store,
}

impl GroupStore {
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// Seed a single round-robin default group from the configured addresses, only when no group
    /// exists yet. Returns whether anything was written.
    ///
    /// # Errors
    /// Store failure.
    pub async fn seed_default(&self, addrs: &[SocketAddr]) -> Result<bool, GroupStoreError> {
        if addrs.is_empty() || !self.list().await?.is_empty() {
            return Ok(false);
        }
        let members = addrs
            .iter()
            .map(|a| GroupMember {
                upstream: Upstream {
                    transport: UpstreamTransport::Udp,
                    host: a.ip().to_string(),
                    port: a.port(),
                    sni: None,
                    spki_pin: None,
                },
                weight: 1,
            })
            .collect();
        self.put(&GroupSpec {
            name: DEFAULT_GROUP.to_owned(),
            strategy: Strategy::RoundRobin,
            default: true,
            domains: Vec::new(),
            members,
        })
        .await?;
        Ok(true)
    }

    /// Insert or replace a group and its members. A default group demotes any other default.
    ///
    /// # Errors
    /// Store failure.
    pub async fn put(&self, spec: &GroupSpec) -> Result<(), GroupStoreError> {
        let spec = spec.clone();
        let now = SystemClock.unix_secs();
        self.store
            .write(move |tx| {
                tx.execute("DELETE FROM upstreams WHERE group_name = ?1", [&spec.name])?;
                if spec.default {
                    tx.execute(
                        "UPDATE upstream_groups SET is_default = 0 WHERE name <> ?1",
                        [&spec.name],
                    )?;
                }
                tx.execute(
                    "INSERT INTO upstream_groups (name, strategy, is_default, domains, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(name) DO UPDATE SET strategy = ?2, is_default = ?3, domains = ?4",
                    params![
                        spec.name,
                        spec.strategy.as_str(),
                        spec.default,
                        spec.domains.join("\n"),
                        now
                    ],
                )?;
                for (pos, m) in spec.members.iter().enumerate() {
                    tx.execute(
                        "INSERT INTO upstreams (group_name, url, weight, position)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![
                            spec.name,
                            m.upstream.to_string(),
                            m.weight,
                            i64::try_from(pos).unwrap_or(i64::MAX)
                        ],
                    )?;
                }
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Delete a group and its members; returns whether it existed.
    ///
    /// # Errors
    /// Store failure.
    pub async fn delete(&self, name: &str) -> Result<bool, GroupStoreError> {
        let name = name.to_owned();
        let n = self
            .store
            .write(move |tx| {
                tx.execute("DELETE FROM upstreams WHERE group_name = ?1", [&name])?;
                Ok(tx.execute("DELETE FROM upstream_groups WHERE name = ?1", [&name])?)
            })
            .await?;
        Ok(n > 0)
    }

    /// All groups ordered by name, members in configured order.
    ///
    /// # Errors
    /// Store failure or a corrupt row.
    pub async fn list(&self) -> Result<Vec<GroupSpec>, GroupStoreError> {
        type GroupRow = (String, String, bool, String);
        type MemberRow = (String, String, u32);
        let (groups, members): (Vec<GroupRow>, Vec<MemberRow>) = self
            .store
            .read(|c| {
                let groups = c
                    .prepare(
                        "SELECT name, strategy, is_default, domains FROM upstream_groups
                         ORDER BY name",
                    )?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                    .collect::<Result<_, _>>()?;
                let members = c
                    .prepare(
                        "SELECT group_name, url, weight FROM upstreams
                         ORDER BY group_name, position",
                    )?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<Result<_, _>>()?;
                Ok((groups, members))
            })
            .await?;
        groups
            .into_iter()
            .map(|(name, strategy, default, domains)| {
                let members = members
                    .iter()
                    .filter(|(g, _, _)| *g == name)
                    .map(|(_, url, weight)| {
                        Ok(GroupMember {
                            upstream: url.parse().map_err(|_| GroupStoreError::Corrupt)?,
                            weight: *weight,
                        })
                    })
                    .collect::<Result<_, GroupStoreError>>()?;
                Ok(GroupSpec {
                    strategy: Strategy::parse(&strategy).ok_or(GroupStoreError::Corrupt)?,
                    default,
                    domains: domains
                        .split('\n')
                        .filter(|d| !d.is_empty())
                        .map(str::to_owned)
                        .collect(),
                    members,
                    name,
                })
            })
            .collect()
    }
}
