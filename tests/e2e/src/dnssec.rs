//! DNSSEC fixtures: a tree of signed (and unsigned) zones, root first, served by the fake
//! upstream as if it were the authoritative infrastructure behind a recursive resolver.
//!
//! The configuration accepts trust anchors for the root only, so every fixture hangs off a signed
//! root: `. -> test. -> example.test.`, each delegation carrying the DS of the child's key. A
//! zone can be unsigned, signed with NSEC or NSEC3 (opt-out too), signed in the past or the
//! future, published with a missing, unsupported or mismatching DS, or flooded with DNSKEYs that
//! share the signing key's tag (`KeyTrap`).
//!
//! The responder answers like an authoritative server for the deepest zone that owns the name:
//! positive answers with their RRSIGs, wildcard expansions, NODATA and NXDOMAIN with the SOA and
//! every NSEC or NSEC3 record of the zone (the fixtures are small, so the proof is always
//! contained). Tests forge a response by taking [`Tree::answer`], editing it and scripting it
//! with [`FakeUpstream::on`](crate::FakeUpstream::on).

use dnsy_core::{Clock as _, SystemClock};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use dnsy_core::{KeyRole, KeyState};
use dnsy_dnssec::{
    ActiveKeys, Algorithm, Denial, DigestType, SignedZone, SigningKey, SigningPolicy, ZoneData,
    ZoneKey, ZoneSigner, ds_for,
};
use dnsy_proto::{Class, Dnskey, Name, RData, Rcode, Record, RecordType, Soa};

use crate::upstream::{FakeUpstream, Reply, rec};

/// What the parent zone publishes for a signed child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DsMode {
    /// A matching SHA-256 DS.
    Normal,
    /// No DS: the delegation is insecure.
    Missing,
    /// A DS for an algorithm the validator does not implement (RFC 4035 5.2: insecure).
    UnsupportedAlgorithm(u8),
    /// A DS with the right tag and algorithm but a digest that matches no key.
    WrongDigest,
    /// A DS whose key tag matches no DNSKEY of the child.
    UnknownKeyTag,
}

/// How one zone of the tree is built.
#[derive(Clone, Debug)]
pub struct ZoneSpec {
    origin: Name,
    records: Vec<Record>,
    signed: bool,
    denial: Denial,
    algorithm: Algorithm,
    split_keys: bool,
    ds: DsMode,
    signed_offset: i64,
    junk_keys: usize,
}

impl ZoneSpec {
    /// A signed zone (ECDSA P-256, KSK and ZSK, NSEC) named `origin` (with trailing dot).
    pub fn new(origin: &str) -> ZoneSpec {
        ZoneSpec {
            origin: Name::from_ascii(origin).expect("zone name"),
            records: Vec::new(),
            signed: true,
            denial: Denial::Nsec,
            algorithm: Algorithm::EcdsaP256Sha256,
            split_keys: true,
            ds: DsMode::Normal,
            signed_offset: 0,
            junk_keys: 0,
        }
    }

    /// An unsigned zone.
    #[must_use]
    pub fn unsigned(mut self) -> Self {
        self.signed = false;
        self
    }

    /// Adds a record whose owner is `name` (relative to the zone, `@` for the apex).
    #[must_use]
    pub fn record(mut self, name: &str, ttl: u32, rtype: RecordType, rdata: &str) -> Self {
        self.records
            .push(rec(&self.absolute(name), ttl, rtype, rdata));
        self
    }

    /// Adds an A record (TTL 300).
    #[must_use]
    pub fn a(self, name: &str, ip: &str) -> Self {
        self.record(name, 300, RecordType::A, ip)
    }

    /// Adds a delegation with no DS and no zone behind it (an unsigned child).
    #[must_use]
    pub fn delegation(self, name: &str) -> Self {
        self.record(name, 300, RecordType::Ns, "ns.fixture.invalid.")
    }

    /// NSEC3 denial without salt and with zero iterations (RFC 9276).
    #[must_use]
    pub fn nsec3(mut self, opt_out: bool) -> Self {
        self.denial = Denial::Nsec3 {
            iterations: 0,
            salt: Vec::new(),
            opt_out,
        };
        self
    }

    #[must_use]
    pub fn algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// One CSK instead of a KSK and a ZSK.
    #[must_use]
    pub fn csk(mut self) -> Self {
        self.split_keys = false;
        self
    }

    /// What the parent publishes as DS for this zone.
    #[must_use]
    pub fn ds(mut self, mode: DsMode) -> Self {
        self.ds = mode;
        self
    }

    /// Signs as if `secs` seconds from now (negative: in the past, so the RRSIGs are expired).
    #[must_use]
    pub fn signed_offset(mut self, secs: i64) -> Self {
        self.signed_offset = secs;
        self
    }

    /// Adds `n` DNSKEYs with the signing ZSK's tag and algorithm (and no private key): every
    /// signature check has to try them all (`KeyTrap`, CVE-2023-50387).
    #[must_use]
    pub fn colliding_keys(mut self, n: usize) -> Self {
        self.junk_keys = n;
        self
    }

    fn absolute(&self, name: &str) -> String {
        if name == "@" {
            self.origin.to_string()
        } else if name.ends_with('.') {
            name.to_owned()
        } else {
            format!("{name}.{}", self.origin)
        }
    }
}

/// A response as the upstream would send it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub rcode: Rcode,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
}

impl Answer {
    /// The reply that makes the fake upstream send this answer.
    pub fn reply(&self) -> Reply {
        Reply::Message {
            rcode: self.rcode,
            answers: self.answers.clone(),
            authority: self.authority.clone(),
        }
    }

    /// Drops every record of type `rtype` from both sections.
    #[must_use]
    pub fn without(mut self, rtype: RecordType) -> Self {
        self.answers.retain(|r| r.rtype != rtype);
        self.authority.retain(|r| r.rtype != rtype);
        self
    }

    /// Applies `f` to the RRSIG rdata of every signature in both sections.
    #[must_use]
    pub fn map_rrsigs(mut self, mut f: impl FnMut(&mut dnsy_proto::Rrsig)) -> Self {
        for r in self.answers.iter_mut().chain(&mut self.authority) {
            if let RData::Rrsig(s) = &mut r.data {
                f(s);
            }
        }
        self
    }
}

/// One zone of the tree as served.
#[derive(Debug)]
pub struct Served {
    pub origin: Name,
    pub signed: bool,
    rrsets: BTreeMap<(Name, u16), (Vec<Record>, Vec<Record>)>,
    /// NSEC or NSEC3 records with their RRSIGs.
    denial: Vec<Record>,
    /// The DS records the parent publishes for this zone (empty for the root).
    pub ds: Vec<Record>,
    /// The key-signing (or combined) key.
    pub ksk: Option<Dnskey>,
}

impl Served {
    fn soa(&self) -> Vec<Record> {
        self.rrsets
            .get(&(self.origin.clone(), u16::from(RecordType::Soa)))
            .map(|(r, s)| r.iter().chain(s).cloned().collect())
            .unwrap_or_default()
    }

    fn names(&self) -> BTreeSet<Name> {
        let mut names = BTreeSet::new();
        for (name, _) in self.rrsets.keys() {
            let mut n = Some(name.clone());
            while let Some(cur) = n {
                if !cur.is_subdomain_of(&self.origin) || !names.insert(cur.clone()) {
                    break;
                }
                n = cur.parent();
            }
        }
        names
    }

    fn rrset(&self, name: &Name, rtype: RecordType) -> Option<Vec<Record>> {
        self.rrsets
            .get(&(name.clone(), u16::from(rtype)))
            .map(|(r, s)| r.iter().chain(s).cloned().collect())
    }

    fn has_owner(&self, name: &Name) -> bool {
        self.rrsets.keys().any(|(n, _)| n == name)
    }

    fn lookup(&self, qname: &Name, qtype: RecordType) -> Answer {
        let ok = |answers| Answer {
            rcode: Rcode::NoError,
            answers,
            authority: Vec::new(),
        };
        if let Some(found) = self.rrset(qname, qtype) {
            return ok(found);
        }
        let negative = |rcode| {
            let mut authority = self.soa();
            authority.extend(self.denial.iter().cloned());
            Answer {
                rcode,
                answers: Vec::new(),
                authority,
            }
        };
        let names = self.names();
        if names.contains(qname) {
            // The name exists (possibly as an empty non-terminal) without this type.
            return negative(Rcode::NoError);
        }
        // Closest encloser, then its wildcard.
        let mut ce = qname.parent();
        while let Some(c) = ce {
            if names.contains(&c) {
                let wild = Name::from_ascii(&format!("*.{c}")).expect("wildcard name");
                if self.has_owner(&wild) {
                    return match self.rrset(&wild, qtype) {
                        Some(found) => {
                            let mut answers: Vec<Record> = found
                                .into_iter()
                                .map(|mut r| {
                                    r.name = qname.clone();
                                    r
                                })
                                .collect();
                            // Wildcard answers carry the proof that the name does not exist.
                            answers.sort_by_key(|r| r.rtype == RecordType::Rrsig);
                            Answer {
                                rcode: Rcode::NoError,
                                answers,
                                authority: self.denial.clone(),
                            }
                        }
                        None => negative(Rcode::NoError),
                    };
                }
                break;
            }
            ce = c.parent();
        }
        negative(Rcode::NxDomain)
    }
}

/// The built tree of zones.
pub struct Tree {
    zones: Vec<Served>,
    /// The root zone's DS as a `[dnssec] trust_anchors` entry (`keytag algorithm digest-type hex`).
    pub trust_anchor: String,
}

fn now_unix() -> i64 {
    SystemClock.unix_secs()
}

fn soa_record(origin: &Name) -> Record {
    Record {
        name: origin.clone(),
        rtype: RecordType::Soa,
        class: Class::In,
        ttl: 300,
        data: RData::Soa(Soa {
            mname: Name::from_ascii("ns.fixture.invalid.").expect("name"),
            rname: Name::from_ascii("hostmaster.fixture.invalid.").expect("name"),
            serial: 1,
            refresh: 7200,
            retry: 3600,
            expire: 1_209_600,
            minimum: 300,
        }),
    }
}

/// A DNSKEY with `template`'s flags and algorithm, a 64-octet key made unique by `index`, and
/// the key tag `tag` (the last two octets are solved for).
fn colliding_dnskey(template: &Dnskey, tag: u16, index: usize) -> Dnskey {
    let mut key = Dnskey {
        flags: template.flags,
        protocol: 3,
        algorithm: template.algorithm,
        public_key: vec![0; 64],
    };
    // Leading zero octets sort these keys ahead of the real one in the RRset.
    key.public_key[2] = u8::try_from(index >> 8).expect("index");
    key.public_key[3] = u8::try_from(index & 0xff).expect("index");
    for last in 0..=u16::MAX {
        key.public_key[62..].copy_from_slice(&last.to_be_bytes());
        if key.key_tag() == tag {
            return key;
        }
    }
    unreachable!("some final word always reaches a given tag");
}

struct Built {
    served: Served,
}

#[expect(
    clippy::too_many_lines,
    reason = "one linear fixture builder: records, keys, signing, DS"
)]
fn build_zone(spec: &ZoneSpec, children: &[(&ZoneSpec, &Served)]) -> Built {
    let mut records = spec.records.clone();
    records.push(soa_record(&spec.origin));
    records.push(rec(
        &spec.origin.to_string(),
        300,
        RecordType::Ns,
        "ns.fixture.invalid.",
    ));
    for (child_spec, child) in children {
        records.push(rec(
            &child.origin.to_string(),
            300,
            RecordType::Ns,
            "ns.fixture.invalid.",
        ));
        if child_spec.signed {
            records.extend(child.ds.iter().cloned());
        }
    }
    if !spec.signed {
        let mut rrsets: BTreeMap<(Name, u16), (Vec<Record>, Vec<Record>)> = BTreeMap::new();
        for r in records {
            rrsets
                .entry((r.name.clone(), u16::from(r.rtype)))
                .or_default()
                .0
                .push(r);
        }
        return Built {
            served: Served {
                origin: spec.origin.clone(),
                signed: false,
                rrsets,
                denial: Vec::new(),
                ds: Vec::new(),
                ksk: None,
            },
        };
    }
    let (keys, ksk) = if spec.split_keys {
        let ksk = SigningKey::generate(spec.algorithm, true).expect("ksk");
        let zsk = SigningKey::generate(spec.algorithm, false).expect("zsk");
        let ksk_pub = ksk.dnskey();
        let zsk_pub = zsk.dnskey();
        let mut keys = vec![
            ZoneKey::new(KeyRole::Ksk, KeyState::Active, ksk),
            ZoneKey::new(KeyRole::Zsk, KeyState::Active, zsk),
        ];
        for i in 0..spec.junk_keys {
            keys.push(ZoneKey::public(
                KeyRole::Zsk,
                KeyState::Published,
                colliding_dnskey(&zsk_pub, zsk_pub.key_tag(), i),
            ));
        }
        (keys, ksk_pub)
    } else {
        let csk = SigningKey::generate(spec.algorithm, true).expect("csk");
        let csk_pub = csk.dnskey();
        let mut keys = vec![ZoneKey::new(KeyRole::Csk, KeyState::Active, csk)];
        for i in 0..spec.junk_keys {
            keys.push(ZoneKey::public(
                KeyRole::Zsk,
                KeyState::Published,
                colliding_dnskey(&csk_pub, csk_pub.key_tag(), i),
            ));
        }
        (keys, csk_pub)
    };
    let at = u32::try_from(now_unix() + spec.signed_offset).expect("signing time");
    let signed: SignedZone = ZoneSigner::sign(
        &ZoneData {
            origin: spec.origin.clone(),
            records,
        },
        &ActiveKeys { keys },
        &SigningPolicy {
            denial: spec.denial.clone(),
            signature_validity_days: 14,
            refresh_days: 5,
            dnskey_ttl: 300,
        },
        at,
    )
    .expect("sign fixture zone");
    let mut rrsets = BTreeMap::new();
    let mut denial = Vec::new();
    for ((name, code), set) in signed.rrsets {
        if matches!(RecordType::from(code), RecordType::Nsec | RecordType::Nsec3) {
            denial.extend(set.records.into_iter().chain(set.rrsigs));
        } else {
            let mut records = set.records;
            if spec.junk_keys > 0 && code == u16::from(RecordType::Dnskey) {
                // The RRSIG covers the canonical order, so the order served is free: put the
                // colliding keys ahead of the real ones, the worst case for a validator that
                // tries keys as they come.
                records.sort_by_key(|r| match &r.data {
                    RData::Dnskey(k) => k.public_key.clone(),
                    _ => Vec::new(),
                });
            }
            rrsets.insert((name, code), (records, set.rrsigs));
        }
    }
    let ds = match spec.ds {
        DsMode::Missing => Vec::new(),
        mode => {
            let real = ds_for(&spec.origin, &ksk, DigestType::Sha256).expect("ds");
            let ds = match mode {
                DsMode::UnsupportedAlgorithm(alg) => dnsy_proto::Ds {
                    algorithm: alg,
                    digest: vec![0x5a; 32],
                    ..real
                },
                DsMode::WrongDigest => dnsy_proto::Ds {
                    digest: vec![0xa5; 32],
                    ..real
                },
                DsMode::UnknownKeyTag => dnsy_proto::Ds {
                    key_tag: real.key_tag ^ 0x5555,
                    ..real
                },
                _ => real,
            };
            vec![Record {
                name: spec.origin.clone(),
                rtype: RecordType::Ds,
                class: Class::In,
                ttl: 300,
                data: RData::Ds(ds),
            }]
        }
    };
    Built {
        served: Served {
            origin: spec.origin.clone(),
            signed: true,
            rrsets,
            denial,
            ds,
            ksk: Some(ksk),
        },
    }
}

impl Tree {
    /// Builds the tree: a signed root with the given zones below it (each attached to its nearest
    /// ancestor in the tree).
    pub fn build(zones: Vec<ZoneSpec>) -> Tree {
        Self::build_with_root(ZoneSpec::new("."), zones)
    }

    /// Like [`build`](Self::build) with a custom root zone.
    pub fn build_with_root(root: ZoneSpec, zones: Vec<ZoneSpec>) -> Tree {
        let mut specs = vec![root];
        specs.extend(zones);
        // Deepest first, so a child exists before its parent needs its DS.
        let mut order: Vec<usize> = (0..specs.len()).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(specs[i].origin.label_count()));
        let mut built: BTreeMap<usize, Served> = BTreeMap::new();
        for &i in &order {
            let spec = &specs[i];
            let children: Vec<(&ZoneSpec, &Served)> = specs
                .iter()
                .enumerate()
                .filter(|(j, c)| {
                    *j != i
                        && c.origin.is_subdomain_of(&spec.origin)
                        && nearest_parent(&specs, *j) == Some(i)
                })
                .filter_map(|(j, c)| built.get(&j).map(|s| (c, s)))
                .collect();
            let served = build_zone(spec, &children).served;
            built.insert(i, served);
        }
        let root = built.remove(&0).expect("root");
        let ksk = root.ksk.clone().expect("the root is signed");
        let ds = ds_for(&Name::root(), &ksk, DigestType::Sha256).expect("root ds");
        let trust_anchor = format!(
            "{} {} {} {}",
            ds.key_tag,
            ds.algorithm,
            ds.digest_type,
            crate::hex(&ds.digest).to_uppercase()
        );
        let mut zones: Vec<Served> = built.into_values().collect();
        zones.push(root);
        Tree {
            zones,
            trust_anchor,
        }
    }

    /// The zone served under `origin`.
    pub fn zone(&self, origin: &str) -> &Served {
        let origin = Name::from_ascii(origin).expect("zone name");
        self.zones
            .iter()
            .find(|z| z.origin == origin)
            .expect("zone in the tree")
    }

    /// The zone that answers `qname`/`qtype`: the deepest one owning the name, except that DS
    /// is answered by the parent side of the cut.
    fn authority(&self, qname: &Name, qtype: RecordType) -> Option<&Served> {
        self.zones
            .iter()
            .filter(|z| qname.is_subdomain_of(&z.origin))
            .filter(|z| qtype != RecordType::Ds || *qname != z.origin)
            .max_by_key(|z| z.origin.label_count())
    }

    /// What the authoritative servers answer for `qname`/`qtype` (with DNSSEC records).
    pub fn answer(&self, qname: &str, qtype: RecordType) -> Answer {
        let qname = Name::from_ascii(qname).expect("query name");
        match self.authority(&qname, qtype) {
            Some(zone) => zone.lookup(&qname, qtype),
            None => Answer {
                rcode: Rcode::Refused,
                answers: Vec::new(),
                authority: Vec::new(),
            },
        }
    }

    /// The records (and RRSIGs) of one `RRset` as served.
    pub fn rrset(&self, qname: &str, qtype: RecordType) -> Vec<Record> {
        self.answer(qname, qtype).answers
    }

    /// Makes `upstream` answer from the tree (DO queries get the DNSSEC records, others none).
    pub fn serve(self: &Arc<Self>, upstream: &FakeUpstream) {
        let tree = Arc::clone(self);
        upstream.set_responder(Arc::new(move |name, rtype, do_bit| {
            let mut a = tree.answer(&name.to_string(), rtype);
            if !do_bit {
                for section in [&mut a.answers, &mut a.authority] {
                    section.retain(|r| {
                        !matches!(
                            r.rtype,
                            RecordType::Rrsig | RecordType::Nsec | RecordType::Nsec3
                        )
                    });
                }
            }
            Some(a.reply())
        }));
    }
}

/// Index of the nearest proper ancestor zone of `specs[j]` among `specs`.
fn nearest_parent(specs: &[ZoneSpec], j: usize) -> Option<usize> {
    specs
        .iter()
        .enumerate()
        .filter(|(i, s)| {
            *i != j && specs[j].origin.is_subdomain_of(&s.origin) && s.origin != specs[j].origin
        })
        .max_by_key(|(_, s)| s.origin.label_count())
        .map(|(i, _)| i)
}

// ---------------------------------------------------------------------------------------
// test helpers shared by the DNSSEC suites

use dnsy_proto::{EdnsOption, Message};

use crate::harness::{Harness, Opts};

/// A query for `name`/`rtype` with the DO bit set.
pub fn dnssec_query(name: &str, rtype: RecordType) -> Message {
    let mut q = crate::query_edns(name, rtype, 1232);
    if let Some(e) = &mut q.edns {
        e.dnssec_ok = true;
    }
    q
}

/// The same query with the CD bit set (checking disabled).
pub fn checking_disabled(mut q: Message) -> Message {
    q.header.cd = true;
    q
}

/// The extended DNS error codes of a response.
pub fn ede_codes(m: &Message) -> Vec<u16> {
    m.edns
        .iter()
        .flat_map(|e| &e.options)
        .filter_map(|o| match o {
            EdnsOption::ExtendedError { code, .. } => Some(*code),
            _ => None,
        })
        .collect()
}

/// The address of the first A record of a response.
pub fn first_a(m: &Message) -> String {
    match &m.answers.first().map(|r| &r.data) {
        Some(RData::A(ip)) => ip.to_string(),
        other => panic!("no A record first in {other:?}"),
    }
}

/// Starts a server forwarding to a fake upstream that serves `tree`, validating in `mode`
/// (`off`, `permissive` or `strict`) with the tree's root as the only trust anchor.
pub async fn start_validating(tree: &Arc<Tree>, mode: &'static str) -> Harness {
    start_with(
        tree,
        Opts {
            validation: mode,
            ..Opts::default()
        },
    )
    .await
}

/// Like [`start_validating`] with arbitrary options (the trust anchor is filled in).
pub async fn start_with(tree: &Arc<Tree>, mut opts: Opts) -> Harness {
    let upstream = FakeUpstream::start().await;
    tree.serve(&upstream);
    opts.trust_anchors = vec![tree.trust_anchor.clone()];
    Harness::start_with(opts, Some(upstream)).await
}

/// The fake upstream behind a harness started with [`start_with`].
pub fn upstream(h: &Harness) -> &FakeUpstream {
    h.upstream.as_ref().expect("the harness has an upstream")
}

// ---------------------------------------------------------------------------------------
// validating the server's own answers on the client side

use std::net::SocketAddr;

use dnsy_dnssec::{DnssecFetcher, FetchError, TrustAnchors, ValidationOutcome, Validator};
use dnsy_proto::{Ds, Question};

/// Fetches DS and DNSKEY records from a server over UDP (DO and CD set), for [`Validator`].
pub struct WireFetcher(pub SocketAddr);

impl DnssecFetcher for WireFetcher {
    async fn fetch(&self, q: Question) -> Result<Message, FetchError> {
        let mut m = checking_disabled(dnssec_query(&q.name.to_string(), q.qtype));
        m.header.rd = true;
        let bytes = crate::udp_raw(self.0, &crate::clients::wire(&m), crate::DEADLINE)
            .await
            .ok_or_else(|| FetchError("no reply".to_owned()))?;
        Message::decode(&bytes).map_err(|e| FetchError(e.to_string()))
    }
}

/// Parses a DS from the API's export (`key_tag`, `algorithm`, `digest_type`, upper-case hex).
pub fn ds_from_export(v: &serde_json::Value) -> Ds {
    let hex = v["digest"].as_str().expect("digest");
    let digest = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    Ds {
        key_tag: u16::try_from(v["key_tag"].as_u64().expect("tag")).expect("u16"),
        algorithm: u8::try_from(v["algorithm"].as_u64().expect("alg")).expect("u8"),
        digest_type: u8::try_from(v["digest_type"].as_u64().expect("dt")).expect("u8"),
        digest,
    }
}

/// Trust anchors with one DS anchor for `zone` (a zone's DS as handed to its parent).
pub fn anchors_for(zone: &str, ds: Ds) -> TrustAnchors {
    let mut anchors = TrustAnchors::new();
    anchors.add_ds(Name::from_ascii(zone).expect("zone"), ds);
    anchors
}

/// Validates `resp` (the answer of the server at `addr` to `q`) like a validating resolver
/// would: fetching DS and DNSKEY from the same server, starting at `anchors`.
pub async fn validate_answer(
    addr: SocketAddr,
    anchors: TrustAnchors,
    q: &Message,
    resp: &Message,
) -> ValidationOutcome {
    let now = u32::try_from(now_unix()).expect("unix time");
    Validator::new(anchors)
        .validate(&WireFetcher(addr), &q.questions[0], resp, now)
        .await
}

// ---------------------------------------------------------------------------------------
// clock sanity

/// The build timestamp the server logged at start (`build_time=<unix>`).
pub fn logged_build_time(h: &Harness) -> String {
    let logs = h.logs();
    let after = logs
        .split("build_time")
        .nth(1)
        .expect("the start-up log names the build time");
    let bytes = after.as_bytes();
    (0..bytes.len().saturating_sub(10))
        .map(|i| &bytes[i..i + 10])
        .find(|w| w.iter().all(u8::is_ascii_digit))
        .map(|w| String::from_utf8_lossy(w).into_owned())
        .expect("a ten digit build time in the log")
}

/// Copies the `dnsy` binary into `dir` with its embedded build timestamp `stamp` replaced by
/// `9999999999` (year 2286), so the system clock looks earlier than the build: there is no way
/// to move the clock of a child process, and this is the only input of the clock-sanity check.
pub fn binary_from_the_future(dir: &std::path::Path, stamp: &str) -> std::path::PathBuf {
    assert_eq!(stamp.len(), 10, "a ten digit unix time");
    let mut bytes = std::fs::read(crate::harness::binary()).expect("read the dnsy binary");
    let needle = stamp.as_bytes();
    let mut replaced = 0;
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            bytes[i..i + needle.len()].copy_from_slice(b"9999999999");
            replaced += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    assert!(
        replaced > 0,
        "the build timestamp is embedded in the binary"
    );
    let path = dir.join("dnsy-future");
    std::fs::write(&path, bytes).expect("write the patched binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("make it executable");
    }
    path
}
