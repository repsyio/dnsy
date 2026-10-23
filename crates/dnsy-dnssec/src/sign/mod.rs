//! Zone signing (RFC 4035 2, RFC 5155 7, RFC 6781, RFC 7344, RFC 9276).
//!
//! [`ZoneSigner::sign`] turns the records of one zone into a [`SignedZone`]: every
//! authoritative `RRset` signed by the zone-signing keys, the apex DNSKEY `RRset` signed by
//! the key-signing keys, an NSEC or NSEC3 chain (with NSEC3PARAM) and, during a KSK or CSK
//! rollover, CDS and CDNSKEY. Delegation NS `RRsets` and glue stay unsigned; DS at a
//! delegation is signed. [`ZoneSigner::resign`] reuses the signatures of a previous snapshot
//! until they come within `refresh_days` of expiry.

mod chain;
mod parallel;
#[cfg(test)]
mod tests;

use crate::{DigestType, DnssecError, SigningKey, ds_for};
use chain::{ChainNode, NSEC3_SHA1, NameHashes, nsec_chain, nsec3_chain};
use dnsy_core::{KeyRole, KeyState};
use dnsy_proto::{
    Class, Dnskey, Name, Nsec3Param, RData, Record, RecordType, canonical, serial_lt,
};
use ring::digest::{SHA256, digest};
use std::collections::BTreeMap;

const DAY: u32 = 86_400;
/// Signatures start one hour in the past to tolerate validators with slow clocks.
const INCEPTION_OFFSET: u32 = 3600;
/// Longest validity window serial arithmetic can order (RFC 1982): 2^31 - 1 seconds.
const MAX_VALIDITY: u32 = 0x7fff_ffff;

/// The records of one zone, as input to the signer. The SOA must be among `records`; the
/// signer generates every DNSSEC record itself, so DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM,
/// CDS and CDNSKEY are rejected. DS is accepted at delegation points only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneData {
    pub origin: Name,
    pub records: Vec<Record>,
}

/// Authenticated denial of existence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// NSEC chain (RFC 4034 4).
    Nsec,
    /// NSEC3 chain with SHA-1 (RFC 5155); RFC 9276 recommends 0 iterations and no salt.
    Nsec3 {
        iterations: u16,
        salt: Vec<u8>,
        /// Leave insecure delegations (NS without DS) out of the chain (RFC 5155 6).
        opt_out: bool,
    },
}

/// How a zone is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningPolicy {
    pub denial: Denial,
    /// Signature lifetime from signing time; must exceed `refresh_days`.
    pub signature_validity_days: u32,
    /// Signatures closer than this to expiry are replaced on re-sign.
    pub refresh_days: u32,
    /// TTL of the DNSKEY, CDS and CDNSKEY `RRsets`.
    pub dnskey_ttl: u32,
}

/// One key of a zone with its role and lifecycle state. Keys that only publish a DNSKEY
/// need no private key (see [`ZoneKey::signs`]).
#[derive(Debug)]
pub struct ZoneKey {
    pub role: KeyRole,
    pub state: KeyState,
    pub dnskey: Dnskey,
    key: Option<SigningKey>,
}

impl ZoneKey {
    /// A key with its private half.
    pub fn new(role: KeyRole, state: KeyState, key: SigningKey) -> ZoneKey {
        ZoneKey {
            role,
            state,
            dnskey: key.dnskey(),
            key: Some(key),
        }
    }

    /// A key known only by its DNSKEY; enough for keys that are published but do not sign.
    pub fn public(role: KeyRole, state: KeyState, dnskey: Dnskey) -> ZoneKey {
        ZoneKey {
            role,
            state,
            dnskey,
            key: None,
        }
    }

    /// True when a key in this role and state makes signatures, so its private key is
    /// needed: active zone-signing keys (ZSK, CSK), and active, published or retired key-signing
    /// keys (KSK, CSK), which double-sign the DNSKEY `RRset` during a rollover. An algorithm
    /// rollover also needs the published and retired zone-signing keys: see [`ZoneKey::signing_flags`].
    pub fn signs(role: KeyRole, state: KeyState) -> bool {
        Self::signs_zone_data(role, state) || Self::signs_dnskeys(role, state)
    }

    fn signs_zone_data(role: KeyRole, state: KeyState) -> bool {
        state == KeyState::Active && role != KeyRole::Ksk
    }

    /// True when a zone-signing key (ZSK, CSK) in `state` and `algorithm` must also sign
    /// the zone data, given the algorithms of the active zone-signing keys: during an
    /// algorithm rollover the zone is double-signed (RFC 6781 4.1.4, RFC 4035 2.2), so a
    /// published or retired key whose algorithm no active key covers signs too, and every
    /// algorithm in the DNSKEY `RRset` has a complete set of signatures.
    fn double_signs(role: KeyRole, state: KeyState, algorithm: u8, active: &[u8]) -> bool {
        role != KeyRole::Ksk
            && matches!(state, KeyState::Published | KeyState::Retired)
            && !active.contains(&algorithm)
    }

    /// For each `(role, state, algorithm number)` of a zone's keys, whether the key makes any
    /// signature, so its private key is needed. Unlike [`ZoneKey::signs`] this includes the
    /// published and retired zone-signing keys of an algorithm rollover.
    pub fn signing_flags(keys: &[(KeyRole, KeyState, u8)]) -> Vec<bool> {
        let active = Self::active_algorithms(keys.iter().copied());
        keys.iter()
            .map(|&(role, state, algorithm)| {
                Self::signs(role, state) || Self::double_signs(role, state, algorithm, &active)
            })
            .collect()
    }

    fn active_algorithms(keys: impl Iterator<Item = (KeyRole, KeyState, u8)>) -> Vec<u8> {
        let mut out = Vec::new();
        for (role, state, algorithm) in keys {
            if Self::signs_zone_data(role, state) && !out.contains(&algorithm) {
                out.push(algorithm);
            }
        }
        out
    }

    fn signs_dnskeys(role: KeyRole, state: KeyState) -> bool {
        role.is_sep()
            && matches!(
                state,
                KeyState::Published | KeyState::Active | KeyState::Retired
            )
    }
}

/// The keys of a zone in the states that matter for signing: published, active and retired
/// keys go into the DNSKEY `RRset`; generated and removed keys are ignored.
#[derive(Debug, Default)]
pub struct ActiveKeys {
    pub keys: Vec<ZoneKey>,
}

/// One `RRset` of a signed zone and its RRSIGs (none for delegation NS, glue and other data
/// at or below a zone cut).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRrset {
    pub records: Vec<Record>,
    pub rrsigs: Vec<Record>,
}

/// A signed snapshot of a zone: every `RRset`, keyed by owner (canonical order, RFC 4034
/// 6.1) and type, including the generated DNSKEY, CDS, CDNSKEY, NSEC, NSEC3 and NSEC3PARAM
/// `RRsets`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedZone {
    pub origin: Name,
    pub rrsets: BTreeMap<(Name, u16), SignedRrset>,
    /// Unix time from which some signature is within `refresh_days` of expiry.
    pub next_resign: u32,
    /// The NSEC3 hash of every chain name, so a re-sign does not hash an unchanged name again.
    nsec3_hashes: Option<Nsec3Hashes>,
}

/// The NSEC3 owner hashes of one snapshot, valid for the iterations and salt they were made
/// with.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Nsec3Hashes {
    iterations: u16,
    salt: Vec<u8>,
    by_name: NameHashes,
}

impl Nsec3Hashes {
    /// The cached hashes of `previous`, if they were made with these parameters.
    fn matching<'a>(
        previous: Option<&'a SignedZone>,
        iterations: u16,
        salt: &[u8],
    ) -> Option<&'a NameHashes> {
        previous
            .and_then(|p| p.nsec3_hashes.as_ref())
            .filter(|h| h.iterations == iterations && h.salt == salt)
            .map(|h| &h.by_name)
    }
}

impl SignedZone {
    /// A snapshot from its `RRsets`, without cached NSEC3 hashes.
    pub fn new(origin: Name, rrsets: BTreeMap<(Name, u16), SignedRrset>, next_resign: u32) -> Self {
        SignedZone {
            origin,
            rrsets,
            next_resign,
            nsec3_hashes: None,
        }
    }

    pub fn rrset(&self, name: &Name, rtype: RecordType) -> Option<&SignedRrset> {
        self.rrsets.get(&(name.clone(), u16::from(rtype)))
    }

    /// Every record in canonical order: each `RRset` followed by its RRSIGs.
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.rrsets
            .values()
            .flat_map(|s| s.records.iter().chain(&s.rrsigs))
    }

    /// The records the signer added (DNSKEY, CDS, CDNSKEY, NSEC, NSEC3, NSEC3PARAM, RRSIG),
    /// in canonical order.
    pub fn dnssec_records(&self) -> impl Iterator<Item = &Record> {
        self.records().filter(|r| is_dnssec_type(r.rtype))
    }

    /// True once some signature is within `refresh_days` of expiry.
    pub fn needs_refresh(&self, now_unix: u32) -> bool {
        !serial_lt(now_unix, self.next_resign)
    }
}

fn is_dnssec_type(t: RecordType) -> bool {
    matches!(
        t,
        RecordType::Dnskey
            | RecordType::Rrsig
            | RecordType::Nsec
            | RecordType::Nsec3
            | RecordType::Nsec3param
            | RecordType::Cds
            | RecordType::Cdnskey
    )
}

/// Signs zone snapshots.
#[derive(Debug, Clone, Copy)]
pub struct ZoneSigner;

impl ZoneSigner {
    /// Signs `zone` from scratch at `now_unix`: inception one hour back, expiration
    /// `signature_validity_days` ahead minus a per-`RRset` jitter that spreads later
    /// re-signing.
    pub fn sign(
        zone: &ZoneData,
        keys: &ActiveKeys,
        policy: &SigningPolicy,
        now_unix: u32,
    ) -> Result<SignedZone, DnssecError> {
        sign_zone(zone, keys, policy, None, now_unix, parallel::cores())
    }

    /// Signs `zone` again, keeping each RRSIG of `previous` whose `RRset` is unchanged, whose
    /// key still signs, and which is more than `refresh_days` from expiry.
    pub fn resign(
        zone: &ZoneData,
        keys: &ActiveKeys,
        policy: &SigningPolicy,
        previous: &SignedZone,
        now_unix: u32,
    ) -> Result<SignedZone, DnssecError> {
        sign_zone(
            zone,
            keys,
            policy,
            Some(previous),
            now_unix,
            parallel::cores(),
        )
    }
}

/// Signature timing derived from the policy.
struct Timing {
    now: u32,
    validity: u32,
    refresh: u32,
    jitter: u32,
}

impl Timing {
    fn new(policy: &SigningPolicy, now: u32) -> Result<Timing, DnssecError> {
        let validity = policy
            .signature_validity_days
            .checked_mul(DAY)
            .filter(|v| *v <= MAX_VALIDITY)
            .ok_or(DnssecError::InvalidValidity)?;
        let refresh = policy.refresh_days.saturating_mul(DAY);
        if refresh == 0 || refresh >= validity {
            return Err(DnssecError::InvalidValidity);
        }
        // A fresh signature never falls due straight away: the jitter stays below half the
        // gap between validity and refresh.
        let jitter = refresh.min(validity - refresh) / 2;
        Ok(Timing {
            now,
            validity,
            refresh,
            jitter,
        })
    }

    fn inception(&self) -> u32 {
        self.now.wrapping_sub(INCEPTION_OFFSET)
    }

    /// Expiration for one `RRset`: deterministic jitter from owner, type and signing time.
    fn expiration(&self, owner: &Name, rtype: RecordType) -> u32 {
        let mut input = owner.to_lowercase().as_wire().to_vec();
        input.extend_from_slice(&u16::from(rtype).to_be_bytes());
        input.extend_from_slice(&self.now.to_be_bytes());
        let d = digest(&SHA256, &input);
        let mut word = [0u8; 4];
        word.copy_from_slice(&d.as_ref()[..4]);
        let jitter = u32::from_be_bytes(word) % self.jitter.max(1);
        self.now.wrapping_add(self.validity - jitter)
    }

    /// True when an RRSIG can be kept: already valid and not within the refresh window.
    fn reusable(&self, inception: u32, expiration: u32) -> bool {
        !serial_lt(self.now, inception)
            && serial_lt(self.now.wrapping_add(self.refresh), expiration)
    }
}

/// Where a name sits relative to zone cuts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Position {
    /// The apex or authoritative data above every cut.
    Authoritative,
    /// A delegation point: only NS and DS are authoritative here, and only DS is signed.
    Cut,
    /// Below a delegation point (glue): unsigned and outside the denial chain.
    Occluded,
}

type Owners = BTreeMap<Name, BTreeMap<u16, Vec<Record>>>;

/// The keys that sign zone data and the keys that sign the `DNSKEY` set, or an error when
/// either set is empty.
fn select_signers(keys: &ActiveKeys) -> Result<(Vec<&SigningKey>, Vec<&SigningKey>), DnssecError> {
    let active = ZoneKey::active_algorithms(
        keys.keys
            .iter()
            .map(|k| (k.role, k.state, k.dnskey.algorithm)),
    );
    let zone_signers: Vec<&SigningKey> = signers(keys, |k| {
        ZoneKey::signs_zone_data(k.role, k.state)
            || ZoneKey::double_signs(k.role, k.state, k.dnskey.algorithm, &active)
    })?;
    let key_signers: Vec<&SigningKey> = signers(keys, |k| ZoneKey::signs_dnskeys(k.role, k.state))?;
    if zone_signers.is_empty() {
        return Err(DnssecError::NoSigningKey("zone data"));
    }
    if key_signers.is_empty() {
        return Err(DnssecError::NoSigningKey("the DNSKEY RRset"));
    }
    Ok((zone_signers, key_signers))
}

fn sign_zone(
    zone: &ZoneData,
    keys: &ActiveKeys,
    policy: &SigningPolicy,
    previous: Option<&SignedZone>,
    now: u32,
    workers: usize,
) -> Result<SignedZone, DnssecError> {
    let timing = Timing::new(policy, now)?;
    if let Denial::Nsec3 { salt, .. } = &policy.denial
        && salt.len() > usize::from(u8::MAX)
    {
        return Err(DnssecError::Nsec3SaltTooLong);
    }
    let origin = &zone.origin;
    let mut owners = group(zone)?;
    let soa = owners
        .get(origin)
        .and_then(|types| types.get(&u16::from(RecordType::Soa)))
        .and_then(|set| set.first())
        .ok_or(DnssecError::InvalidZone("no SOA at the apex"))?;
    let RData::Soa(soa_data) = &soa.data else {
        return Err(DnssecError::InvalidZone("malformed SOA"));
    };
    let denial_ttl = soa_data.minimum.min(soa.ttl);

    let (zone_signers, key_signers) = select_signers(keys)?;

    add_apex_records(&mut owners, origin, keys, policy, denial_ttl)?;

    let (positions, nodes) = classify(&owners, origin)?;

    let (chain, nsec3_hashes) =
        denial_chain(origin, &nodes, denial_ttl, policy, previous, workers)?;
    // Every RRset is signed independently, so the work is split over worker threads. Results
    // come back in canonical order, which keeps the output identical to a serial pass. Chain
    // records are RRsets of their own (one NSEC per node, one NSEC3 per hash), so they become
    // jobs directly instead of going through `owners`.
    let mut jobs = Vec::new();
    let authoritative = |position: Position, rtype: RecordType| match (position, rtype) {
        (Position::Occluded, _) => Duty::None,
        // At a cut only DS and the NSEC proving the delegation are authoritative.
        (Position::Cut, t) if !matches!(t, RecordType::Ds | RecordType::Nsec) => Duty::None,
        (_, RecordType::Dnskey) => Duty::Dnskeys,
        (_, RecordType::Cds | RecordType::Cdnskey) => Duty::Both,
        _ => Duty::Zone,
    };
    jobs.reserve(chain.len() + owners.len());
    // An NSEC sits at a node (cut or not), in node order; an NSEC3 at a hashed name of its own.
    let node_positions = nodes
        .iter()
        .map(|n| Some(n.position))
        .chain(std::iter::repeat(None));
    for (r, node_position) in chain.into_iter().zip(node_positions) {
        let position = if r.rtype == RecordType::Nsec {
            node_position.unwrap_or(Position::Authoritative)
        } else {
            Position::Authoritative
        };
        jobs.push(Job {
            key: (r.name.clone(), u16::from(r.rtype)),
            duty: authoritative(position, r.rtype),
            records: vec![r],
        });
    }
    for ((name, types), position) in owners.into_iter().zip(positions) {
        for (code, records) in types {
            jobs.push(Job {
                key: (name.clone(), code),
                duty: authoritative(position, RecordType::from(code)),
                records,
            });
        }
    }
    let signers = Signers {
        zone: &zone_signers,
        dnskeys: &key_signers,
    };
    let signed = parallel::map_with(jobs, workers, |job| {
        sign_job(job, &signers, previous, origin, &timing)
    });
    let mut sets = Vec::with_capacity(signed.len());
    let mut next_resign: Option<u32> = None;
    for result in signed {
        let (key, set) = result?;
        for rrsig in &set.rrsigs {
            if let RData::Rrsig(sig) = &rrsig.data {
                let due = sig.expiration.wrapping_sub(timing.refresh);
                next_resign = Some(match next_resign {
                    Some(at) if serial_lt(at, due) => at,
                    _ => due,
                });
            }
        }
        sets.push((key, set));
    }
    let rrsets: BTreeMap<_, _> = sets.into_iter().collect();
    Ok(SignedZone {
        origin: origin.clone(),
        rrsets,
        next_resign: next_resign.unwrap_or(now),
        nsec3_hashes,
    })
}

/// The NSEC or NSEC3 chain of `nodes`, and the NSEC3 hashes it was made from.
fn denial_chain(
    origin: &Name,
    nodes: &[ChainNode],
    denial_ttl: u32,
    policy: &SigningPolicy,
    previous: Option<&SignedZone>,
    workers: usize,
) -> Result<(Vec<Record>, Option<Nsec3Hashes>), DnssecError> {
    Ok(match &policy.denial {
        Denial::Nsec => (nsec_chain(nodes, denial_ttl), None),
        Denial::Nsec3 {
            iterations,
            salt,
            opt_out,
        } => {
            let (records, by_name) = nsec3_chain(
                origin,
                nodes,
                denial_ttl,
                (*iterations, salt),
                *opt_out,
                Nsec3Hashes::matching(previous, *iterations, salt),
                workers,
            )?;
            let hashes = Nsec3Hashes {
                iterations: *iterations,
                salt: salt.clone(),
                by_name,
            };
            (records, Some(hashes))
        }
    })
}

/// Which keys sign an `RRset`.
#[derive(Clone, Copy)]
enum Duty {
    /// Unsigned: delegation NS, glue.
    None,
    /// The zone-signing keys.
    Zone,
    /// The key-signing keys (the DNSKEY `RRset`).
    Dnskeys,
    /// Both sets (CDS and CDNSKEY).
    Both,
}

/// The keys that sign zone data and the DNSKEY `RRset`.
struct Signers<'a> {
    zone: &'a [&'a SigningKey],
    dnskeys: &'a [&'a SigningKey],
}

impl<'a> Signers<'a> {
    fn of(&self, duty: Duty) -> Vec<&'a SigningKey> {
        match duty {
            Duty::None => Vec::new(),
            Duty::Zone => self.zone.to_vec(),
            Duty::Dnskeys => self.dnskeys.to_vec(),
            Duty::Both => union(self.dnskeys, self.zone),
        }
    }
}

/// One `RRset` to sign: its key in the snapshot, its records and which keys sign it.
struct Job {
    key: (Name, u16),
    records: Vec<Record>,
    duty: Duty,
}

fn sign_job(
    job: Job,
    signers: &Signers<'_>,
    previous: Option<&SignedZone>,
    origin: &Name,
    timing: &Timing,
) -> Result<((Name, u16), SignedRrset), DnssecError> {
    let Job { key, records, duty } = job;
    let old = previous
        .and_then(|p| p.rrsets.get(&key))
        .filter(|old| same_data(&old.records, &records));
    let rrsigs = signers
        .of(duty)
        .into_iter()
        .map(|signer| rrsig_for(signer, &records, old, origin, timing))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((key, SignedRrset { records, rrsigs }))
}

/// Classifies every owner relative to zone cuts and collects the nodes of the denial chain.
fn classify(
    owners: &Owners,
    origin: &Name,
) -> Result<(Vec<Position>, Vec<ChainNode>), DnssecError> {
    // Classify names and collect the denial chain; canonical order puts every name right
    // after its ancestors, so one pass tracks the innermost enclosing cut.
    let mut positions = Vec::with_capacity(owners.len());
    let mut nodes = Vec::new();
    let mut cut: Option<Name> = None;
    for (name, types) in owners {
        let below_cut = cut
            .as_ref()
            .is_some_and(|c| name != c && name.is_subdomain_of(c));
        let has = |t: RecordType| types.contains_key(&u16::from(t));
        let position = if below_cut {
            Position::Occluded
        } else if name != origin && has(RecordType::Ns) {
            cut = Some(name.clone());
            Position::Cut
        } else {
            Position::Authoritative
        };
        if has(RecordType::Ds) && position != Position::Cut {
            return Err(DnssecError::InvalidZone("DS outside a delegation point"));
        }
        let node_types: Vec<RecordType> = match position {
            Position::Occluded => {
                positions.push(position);
                continue;
            }
            Position::Cut => [RecordType::Ns, RecordType::Ds]
                .into_iter()
                .filter(|t| has(*t))
                .collect(),
            Position::Authoritative => types.keys().map(|t| RecordType::from(*t)).collect(),
        };
        let secure = position == Position::Authoritative || has(RecordType::Ds);
        nodes.push(ChainNode {
            name: name.clone(),
            types: node_types,
            signed: secure,
            insecure_cut: !secure,
            position,
        });
        positions.push(position);
    }

    Ok((positions, nodes))
}

/// The RRSIG of `records` by `signer`: the matching one from the previous snapshot when it
/// can be kept, else a fresh signature.
fn rrsig_for(
    signer: &SigningKey,
    records: &[Record],
    old: Option<&SignedRrset>,
    origin: &Name,
    timing: &Timing,
) -> Result<Record, DnssecError> {
    let dnskey = signer.dnskey();
    let kept = old.and_then(|o| {
        o.rrsigs.iter().find(|s| match &s.data {
            RData::Rrsig(sig) => {
                sig.key_tag == dnskey.key_tag()
                    && sig.algorithm == dnskey.algorithm
                    && sig.signer == *origin
                    && timing.reusable(sig.inception, sig.expiration)
            }
            _ => false,
        })
    });
    if let Some(sig) = kept {
        return Ok(sig.clone());
    }
    let first = &records[0];
    signer.sign_rrset(
        records,
        origin,
        timing.inception(),
        timing.expiration(&first.name, first.rtype),
    )
}

/// Groups the zone records into `RRsets` by owner and type, checking that the signer can
/// own the DNSSEC records. Each `RRset` gets the lowest TTL among its records (RFC 2181 5.2).
fn group(zone: &ZoneData) -> Result<Owners, DnssecError> {
    let mut owners: Owners = BTreeMap::new();
    for r in &zone.records {
        if !r.name.is_subdomain_of(&zone.origin) {
            return Err(DnssecError::InvalidZone("record outside the zone"));
        }
        if is_dnssec_type(r.rtype) {
            return Err(DnssecError::InvalidZone(
                "DNSSEC records are generated by the signer",
            ));
        }
        if r.rtype == RecordType::Soa && r.name != zone.origin {
            return Err(DnssecError::InvalidZone("SOA below the apex"));
        }
        if r.rtype == RecordType::Ds && r.name == zone.origin {
            return Err(DnssecError::InvalidZone("DS at the apex"));
        }
        owners
            .entry(r.name.clone())
            .or_default()
            .entry(u16::from(r.rtype))
            .or_default()
            .push(r.clone());
    }
    for set in owners.values_mut().flat_map(BTreeMap::values_mut) {
        let ttl = set.iter().map(|r| r.ttl).min().unwrap_or_default();
        for r in set {
            r.ttl = ttl;
        }
    }
    Ok(owners)
}

fn signers(
    keys: &ActiveKeys,
    duty: impl Fn(&ZoneKey) -> bool,
) -> Result<Vec<&SigningKey>, DnssecError> {
    keys.keys
        .iter()
        .filter(|k| duty(k))
        .map(|k| k.key.as_ref().ok_or(DnssecError::InvalidKey))
        .collect()
}

fn union<'a>(a: &[&'a SigningKey], b: &[&'a SigningKey]) -> Vec<&'a SigningKey> {
    let mut out = a.to_vec();
    for k in b {
        if !out.iter().any(|o| std::ptr::eq(*o, *k)) {
            out.push(k);
        }
    }
    out
}

/// Adds the DNSKEY `RRset`, CDS and CDNSKEY during a key-signing key rollover, and
/// NSEC3PARAM for NSEC3 zones.
fn add_apex_records(
    owners: &mut Owners,
    origin: &Name,
    keys: &ActiveKeys,
    policy: &SigningPolicy,
    denial_ttl: u32,
) -> Result<(), DnssecError> {
    let mk = |ttl: u32, data: RData| Record {
        name: origin.clone(),
        rtype: data.rtype(),
        class: Class::In,
        ttl,
        data,
    };
    let apex = owners.entry(origin.clone()).or_default();
    let mut dnskeys: Vec<&Dnskey> = Vec::new();
    for k in keys.keys.iter().filter(|k| k.state.is_published()) {
        if !dnskeys.contains(&&k.dnskey) {
            dnskeys.push(&k.dnskey);
        }
    }
    apex.insert(
        u16::from(RecordType::Dnskey),
        dnskeys
            .iter()
            .map(|k| mk(policy.dnskey_ttl, RData::Dnskey((*k).clone())))
            .collect(),
    );

    // RFC 7344: while a new SEP key waits for its DS, CDS/CDNSKEY ask the parent for the
    // DS set covering both the old and the new key.
    let sep = |state: KeyState| {
        keys.keys
            .iter()
            .filter(move |k| k.role.is_sep() && k.state == state)
    };
    if sep(KeyState::Published).next().is_some() && sep(KeyState::Active).next().is_some() {
        let mut cds = Vec::new();
        let mut cdnskey = Vec::new();
        for k in sep(KeyState::Active).chain(sep(KeyState::Published)) {
            let ds = ds_for(origin, &k.dnskey, DigestType::Sha256)?;
            cds.push(mk(policy.dnskey_ttl, RData::Cds(ds)));
            cdnskey.push(mk(policy.dnskey_ttl, RData::Cdnskey(k.dnskey.clone())));
        }
        apex.insert(u16::from(RecordType::Cds), cds);
        apex.insert(u16::from(RecordType::Cdnskey), cdnskey);
    }

    if let Denial::Nsec3 {
        iterations, salt, ..
    } = &policy.denial
    {
        apex.insert(
            u16::from(RecordType::Nsec3param),
            vec![mk(
                denial_ttl,
                RData::Nsec3param(Nsec3Param {
                    hash_alg: NSEC3_SHA1,
                    flags: 0,
                    iterations: *iterations,
                    salt: salt.clone(),
                }),
            )],
        );
    }
    Ok(())
}

/// True when two `RRsets` have the same TTL, classes and RDATA (in canonical form, as
/// signed), so a signature over one is valid for the other.
fn same_data(a: &[Record], b: &[Record]) -> bool {
    let key = |set: &[Record]| {
        let mut v: Vec<(u32, u16, Vec<u8>)> = set
            .iter()
            .map(|r| (r.ttl, u16::from(r.class), canonical::rdata_wire(&r.data)))
            .collect();
        v.sort();
        v.dedup();
        v
    };
    key(a) == key(b)
}
