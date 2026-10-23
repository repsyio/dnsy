//! Online-signed zones.
//!
//! [`SignedIndex`] is the DNSSEC overlay of a zone's lookup index: the RRSIGs of every
//! `RRset` and the NSEC or NSEC3 chain, from which DO answers get their signatures and
//! denial-of-existence proofs (RFC 4035 3.1, RFC 5155 7.2). [`ZoneSigning`] keeps the signed
//! snapshots of a [`ZoneStore`] current: it signs zones with `dnssec.enabled` when they load
//! or change, when their keys change state and when signatures near expiry, and installs each
//! new snapshot with an atomic swap so queries never wait for signing.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::iter;
use std::ops::Bound;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use dnsy_core::Clock;
use dnsy_dnssec::{Algorithm, SignedZone, ZoneSigner, nsec3_hash};
use dnsy_keys::{KeyState, KeyStore, KeyStoreError};
use dnsy_proto::{Name, RData, Record, RecordType, base32hex_encode};

use crate::lookup::LookupResult;
use crate::model::Zone;
use crate::store::{SignedEntry, ZoneStore};

/// A denial-of-existence proof a lookup needs (RFC 4035 3.1.3, RFC 5155 7.2).
#[derive(Debug, Clone)]
pub(crate) enum Proof {
    /// `qname` does not exist; `encloser` is its closest encloser and has no wildcard child.
    NxDomain { qname: Name, encloser: Name },
    /// `qname` exists (possibly as an empty non-terminal) but not with the queried type.
    NoData { qname: Name },
    /// `qname` does not exist; the wildcard below `encloser` matched but lacks the type.
    WildcardNoData { qname: Name, encloser: Name },
    /// `qname` was synthesised from the wildcard below `encloser`.
    WildcardAnswer { qname: Name, encloser: Name },
    /// A delegation without DS: proves the absence of DS at `cut`.
    InsecureDelegation { cut: Name },
}

/// What a lookup records for signing: the proofs it needs and the names it synthesised from
/// wildcards (with the wildcard owner whose RRSIGs cover them). Records nothing unless
/// `enabled`.
#[derive(Debug, Default)]
pub(crate) struct Trace {
    enabled: bool,
    proofs: Vec<Proof>,
    expansions: Vec<(Name, Name)>,
}

impl Trace {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            ..Self::default()
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn proof(&mut self, proof: impl FnOnce() -> Proof) {
        if self.enabled {
            self.proofs.push(proof());
        }
    }

    /// `qname` was synthesised from the wildcard below `encloser`.
    pub(crate) fn expansion(&mut self, qname: &Name, encloser: &Name) {
        if self.enabled
            && let Some(source) = wildcard_of(encloser)
        {
            self.expansions.push((qname.clone(), source));
        }
    }
}

/// `*.<name>`.
pub(crate) fn wildcard_of(name: &Name) -> Option<Name> {
    let star: &[u8] = b"*";
    Name::from_labels(iter::once(star).chain(name.labels())).ok()
}

/// The ancestor of `name` one label below `encloser` (RFC 5155 1.3, "next closer name").
fn next_closer(name: &Name, encloser: &Name) -> Option<Name> {
    let skip = name.label_count().checked_sub(encloser.label_count() + 1)?;
    Name::from_labels(name.labels().skip(usize::from(skip))).ok()
}

/// The lowercase base32hex NSEC3 hash label of `name`.
fn nsec3_key_of(name: &Name, salt: &[u8], iterations: u16) -> String {
    base32hex_encode(&nsec3_hash(name, salt, iterations)).to_ascii_lowercase()
}

/// The authenticated denial chain of a signed zone.
#[derive(Debug)]
enum Chain {
    /// NSEC records by owner, in canonical order.
    Nsec(BTreeMap<Name, Record>),
    /// NSEC3 records by lowercase base32hex hash label; that order is hash order.
    Nsec3 {
        origin: Name,
        iterations: u16,
        salt: Vec<u8>,
        records: BTreeMap<String, Record>,
        /// The hash label of every name of the zone (owners and empty non-terminals), computed
        /// once when the index is built; only names that do not exist are hashed per query.
        owner_keys: BTreeMap<Name, String>,
    },
}

/// RRSIGs and the denial chain of one signed zone snapshot.
#[derive(Debug)]
pub(crate) struct SignedIndex {
    sigs: BTreeMap<(Name, RecordType), Arc<[Record]>>,
    chain: Chain,
}

impl SignedIndex {
    pub(crate) fn build(signed: &SignedZone) -> Self {
        let mut sigs = BTreeMap::new();
        let mut nsec = BTreeMap::new();
        let mut nsec3 = BTreeMap::new();
        let mut params = None;
        for ((owner, code), set) in &signed.rrsets {
            let rtype = RecordType::from(*code);
            if !set.rrsigs.is_empty() {
                sigs.insert((owner.clone(), rtype), Arc::clone(&set.rrsigs));
            }
            for r in set.records.iter() {
                match &r.data {
                    RData::Nsec { .. } => {
                        nsec.insert(owner.clone(), r.clone());
                    }
                    RData::Nsec3(n) => {
                        params.get_or_insert_with(|| (n.iterations, n.salt.clone()));
                        let label = owner.labels().next().unwrap_or_default();
                        nsec3.insert(
                            String::from_utf8_lossy(label).to_ascii_lowercase(),
                            r.clone(),
                        );
                    }
                    _ => {}
                }
            }
        }
        let chain = match params {
            Some((iterations, salt)) => {
                let mut owner_keys = BTreeMap::new();
                for (owner, code) in signed.rrsets.keys() {
                    if RecordType::from(*code) == RecordType::Nsec3 {
                        continue;
                    }
                    let mut cur = Some(owner.clone());
                    while let Some(n) = cur.filter(|n| n.is_subdomain_of(&signed.origin)) {
                        cur = n.parent();
                        if let Entry::Vacant(slot) = owner_keys.entry(n) {
                            let key = nsec3_key_of(slot.key(), &salt, iterations);
                            slot.insert(key);
                        }
                    }
                }
                Chain::Nsec3 {
                    origin: signed.origin.clone(),
                    iterations,
                    salt,
                    records: nsec3,
                    owner_keys,
                }
            }
            None => Chain::Nsec(nsec),
        };
        Self { sigs, chain }
    }

    /// Adds RRSIGs after every `RRset` of `result` and appends the proofs of `trace` to its
    /// authority section (to `ds_or_proof` for a referral).
    pub(crate) fn secure(&self, result: LookupResult, trace: &Trace) -> LookupResult {
        let proofs = self.proofs(trace);
        match result {
            LookupResult::Answer {
                answers,
                authority,
                additional,
            } => {
                let mut authority = self.with_sigs(&authority, trace);
                authority.extend(proofs);
                LookupResult::Answer {
                    answers: self.with_sigs(&answers, trace),
                    authority,
                    additional: self.with_sigs(&additional, trace),
                }
            }
            LookupResult::Referral {
                ns,
                ds_or_proof,
                glue,
            } => {
                let mut ds_or_proof = self.with_sigs(&ds_or_proof, trace);
                ds_or_proof.extend(proofs);
                LookupResult::Referral {
                    ns,
                    ds_or_proof,
                    glue,
                }
            }
            LookupResult::NoData { authority } => {
                let mut authority = self.with_sigs(&authority, trace);
                authority.extend(proofs);
                LookupResult::NoData { authority }
            }
            LookupResult::ServFail => LookupResult::ServFail,
            LookupResult::NxDomain { authority } => {
                let mut authority = self.with_sigs(&authority, trace);
                authority.extend(proofs);
                LookupResult::NxDomain { authority }
            }
        }
    }

    /// Each `RRset` of `records` (runs of one owner and type) followed by its RRSIGs, owned by
    /// the answer's name (the query name for wildcard expansions). Unsigned data (delegation
    /// NS, glue) gets none.
    fn with_sigs(&self, records: &[Record], trace: &Trace) -> Vec<Record> {
        let mut out = Vec::with_capacity(records.len() * 2);
        let mut i = 0;
        while i < records.len() {
            let (name, rtype) = (records[i].name.clone(), records[i].rtype);
            let end = records[i..]
                .iter()
                .position(|r| r.name != name || r.rtype != rtype)
                .map_or(records.len(), |n| i + n);
            out.extend_from_slice(&records[i..end]);
            let source = trace
                .expansions
                .iter()
                .find(|(expanded, _)| *expanded == name)
                .map_or(&name, |(_, source)| source);
            if let Some(sigs) = self.sigs.get(&(source.clone(), rtype)) {
                out.extend(sigs.iter().map(|s| Record {
                    name: name.clone(),
                    ..s.clone()
                }));
            }
            i = end;
        }
        out
    }

    /// The denial records (with their RRSIGs) for every proof of `trace`, each record once.
    fn proofs(&self, trace: &Trace) -> Vec<Record> {
        let mut picked: Vec<&Record> = Vec::new();
        for proof in &trace.proofs {
            for r in self.proof(proof) {
                if !picked.iter().any(|p| p.name == r.name) {
                    picked.push(r);
                }
            }
        }
        let mut out = Vec::new();
        for r in picked {
            out.push(r.clone());
            if let Some(sigs) = self.sigs.get(&(r.name.clone(), r.rtype)) {
                out.extend(sigs.iter().cloned());
            }
        }
        out
    }

    fn proof(&self, proof: &Proof) -> Vec<&Record> {
        match &self.chain {
            Chain::Nsec(records) => {
                let nsec = |name: &Name| records.range(..=name.clone()).next_back().map(|(_, r)| r);
                let wildcard = |encloser: &Name| wildcard_of(encloser).and_then(|w| nsec(&w));
                match proof {
                    // RFC 4035 3.1.3.2 and 3.1.3.4: the NSEC covering the name plus the NSEC
                    // covering (or matching) the wildcard at the closest encloser.
                    Proof::NxDomain { qname, encloser }
                    | Proof::WildcardNoData { qname, encloser } => {
                        nsec(qname).into_iter().chain(wildcard(encloser)).collect()
                    }
                    // RFC 4035 3.1.3.1: the matching NSEC, or for an empty non-terminal the
                    // NSEC whose span contains it. 3.1.3.3: the NSEC covering the query name.
                    Proof::NoData { qname } | Proof::WildcardAnswer { qname, .. } => {
                        nsec(qname).into_iter().collect()
                    }
                    Proof::InsecureDelegation { cut } => nsec(cut).into_iter().collect(),
                }
            }
            Chain::Nsec3 { .. } => match proof {
                // RFC 5155 7.2.2: closest encloser proof plus the wildcard cover.
                Proof::NxDomain { qname, .. } => {
                    let Some((encloser, mut out)) = self.encloser_proof(qname) else {
                        return Vec::new();
                    };
                    out.extend(wildcard_of(&encloser).and_then(|w| self.nsec3_covering(&w)));
                    out
                }
                // RFC 5155 7.2.3, 7.2.4 and 7.2.7: the matching NSEC3, else (opt-out) the
                // closest provable encloser proof.
                Proof::NoData { qname } | Proof::InsecureDelegation { cut: qname } => {
                    match self.nsec3_matching(qname) {
                        Some(m) => vec![m],
                        None => self
                            .encloser_proof(qname)
                            .map(|(_, out)| out)
                            .unwrap_or_default(),
                    }
                }
                // RFC 5155 7.2.5: closest encloser proof plus the NSEC3 matching the wildcard.
                Proof::WildcardNoData { qname, encloser } => {
                    let mut out: Vec<&Record> = self.nsec3_matching(encloser).into_iter().collect();
                    out.extend(next_closer(qname, encloser).and_then(|n| self.nsec3_covering(&n)));
                    out.extend(wildcard_of(encloser).and_then(|w| self.nsec3_matching(&w)));
                    out
                }
                // RFC 5155 7.2.6: the NSEC3 covering the next closer name.
                Proof::WildcardAnswer { qname, encloser } => next_closer(qname, encloser)
                    .and_then(|n| self.nsec3_covering(&n))
                    .into_iter()
                    .collect(),
            },
        }
    }

    fn nsec3_key(&self, name: &Name) -> Option<(Cow<'_, str>, &BTreeMap<String, Record>)> {
        let Chain::Nsec3 {
            iterations,
            salt,
            records,
            owner_keys,
            ..
        } = &self.chain
        else {
            return None;
        };
        let key = owner_keys.get(name).map_or_else(
            || Cow::Owned(nsec3_key_of(name, salt, *iterations)),
            |k| Cow::Borrowed(k.as_str()),
        );
        Some((key, records))
    }

    fn nsec3_matching(&self, name: &Name) -> Option<&Record> {
        let (key, records) = self.nsec3_key(name)?;
        records.get(&*key)
    }

    /// The NSEC3 whose span strictly contains the hash of `name` (the last one wraps).
    fn nsec3_covering(&self, name: &Name) -> Option<&Record> {
        let (key, records) = self.nsec3_key(name)?;
        records
            .range::<str, _>((Bound::Unbounded, Bound::Excluded(&*key)))
            .next_back()
            .or_else(|| records.iter().next_back())
            .map(|(_, r)| r)
    }

    /// RFC 5155 7.2.1: the NSEC3 matching the closest provable encloser of `name` and the one
    /// covering the next closer name, with that encloser.
    fn encloser_proof(&self, name: &Name) -> Option<(Name, Vec<&Record>)> {
        let Chain::Nsec3 { origin, .. } = &self.chain else {
            return None;
        };
        let mut candidate = name.parent();
        while let Some(encloser) = candidate.filter(|n| n.is_subdomain_of(origin)) {
            if let Some(m) = self.nsec3_matching(&encloser) {
                let mut out = vec![m];
                out.extend(next_closer(name, &encloser).and_then(|n| self.nsec3_covering(&n)));
                return Some((encloser, out));
            }
            candidate = encloser.parent();
        }
        None
    }
}

/// Unix time as an RRSIG serial number (RFC 4034 3.1.5: modulo 2^32).
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "RRSIG times are serial numbers modulo 2^32 (RFC 4034 3.1.5)"
)]
fn serial_time(unix: i64) -> u32 {
    unix as u32
}

/// The key ids and states a snapshot was signed with; a change means re-signing.
type KeyFingerprint = Vec<(i64, KeyState)>;

/// Signs the zones of a [`ZoneStore`] that have `dnssec.enabled` and keeps their snapshots
/// fresh. Creating it switches the store to serving signed snapshots; call
/// [`ZoneSigning::sign_due`] once before serving and [`ZoneSigning::spawn`] for the refresh
/// task. Signature times come from the key store's clock.
#[derive(Clone)]
pub struct ZoneSigning {
    inner: Arc<Inner>,
}

struct Inner {
    store: Arc<ZoneStore>,
    keys: KeyStore,
    clock: Arc<dyn Clock>,
    signed_with: Mutex<BTreeMap<Name, KeyFingerprint>>,
}

impl std::fmt::Debug for ZoneSigning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneSigning").finish_non_exhaustive()
    }
}

impl ZoneSigning {
    /// Attaches signing to `store`, with keys (and time) from `keys`.
    pub fn new(store: Arc<ZoneStore>, keys: KeyStore) -> Self {
        store.enable_signing();
        let clock = keys.clock();
        Self {
            inner: Arc::new(Inner {
                store,
                keys,
                clock,
                signed_with: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    /// The key store signing keys come from (shared with key management).
    #[must_use]
    pub fn keys(&self) -> &KeyStore {
        &self.inner.keys
    }

    /// Signs every zone that needs it: never signed, changed since its last signing, keys
    /// changed state, or a signature within `refresh_days` of expiry. Zones without keys get
    /// their initial key set. A failure is logged once per zone and does not stop the others;
    /// the zone keeps serving its previous signed snapshot, or answers SERVFAIL when it was
    /// never signed (see [`ZoneStore::signing_failures`]). Returns how many zones were signed.
    pub async fn sign_due(&self) -> usize {
        let mut signed = 0;
        for (zone, previous) in self.inner.store.signing_state() {
            match self.sign_zone(&zone, previous).await {
                Ok(true) => signed += 1,
                Ok(false) => {
                    self.inner.store.set_signing_failure(&zone.origin, None);
                }
                Err(e) => {
                    // Logged when the failure appears or changes, not on every pass.
                    if self
                        .inner
                        .store
                        .set_signing_failure(&zone.origin, Some(e.to_string()))
                    {
                        tracing::error!(zone = %zone.origin, error = %e, "zone signing failed");
                    }
                }
            }
        }
        signed
    }

    async fn sign_zone(
        &self,
        zone: &Arc<Zone>,
        previous: Option<SignedEntry>,
    ) -> Result<bool, SigningError> {
        let Some(policy) = zone.dnssec.as_ref().filter(|p| p.enabled) else {
            return Ok(false);
        };
        let keys = &self.inner.keys;
        let fingerprint: KeyFingerprint = keys
            .bootstrap(
                &zone.origin,
                policy.key_layout,
                Algorithm::from(policy.algorithm),
            )
            .await?
            .into_iter()
            .filter(|k| k.state != KeyState::Removed)
            .map(|k| (k.id, k.state))
            .collect();
        let now = serial_time(self.inner.clock.unix_secs());
        let keys_changed = self
            .lock()
            .get(&zone.origin)
            .is_none_or(|f| *f != fingerprint);
        let due = match &previous {
            None => true,
            Some(entry) => keys_changed || *entry.zone != **zone || entry.signed.needs_refresh(now),
        };
        if !due {
            return Ok(false);
        }
        let active = keys.active_keys(&zone.origin).await?;
        let signing_policy = policy.signing_policy()?;
        let data = zone.signing_data();
        let snapshot = tokio::task::spawn_blocking(move || match previous {
            Some(p) => ZoneSigner::resign(&data, &active, &signing_policy, &p.signed, now),
            None => ZoneSigner::sign(&data, &active, &signing_policy, now),
        })
        .await
        .map_err(|_| SigningError::Task)??;
        self.inner
            .store
            .install_signed(Arc::clone(zone), Arc::new(snapshot));
        self.lock().insert(zone.origin.clone(), fingerprint);
        tracing::info!(zone = %zone.origin, "zone signed");
        Ok(true)
    }

    /// Spawns the refresh task: signs due zones whenever the store reloads a signed zone and
    /// at least every `interval` (signature refresh and key state changes).
    #[must_use]
    pub fn spawn(self, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let wake = self.inner.store.resign_signal();
            loop {
                tokio::select! {
                    () = wake.notified() => {}
                    () = tokio::time::sleep(interval) => {}
                }
                self.sign_due().await;
            }
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<Name, KeyFingerprint>> {
        self.inner
            .signed_with
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Why a zone could not be signed.
#[derive(Debug, thiserror::Error)]
enum SigningError {
    #[error(transparent)]
    Keys(#[from] KeyStoreError),
    #[error(transparent)]
    Policy(#[from] crate::model::ZoneError),
    #[error(transparent)]
    Sign(#[from] dnsy_dnssec::DnssecError),
    #[error("signing task failed")]
    Task,
}

#[cfg(test)]
#[path = "signed_tests.rs"]
mod tests;
