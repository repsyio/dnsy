//! DNSY-37: DNSSEC validation in the forwarding path, against an in-memory signed `example.`
//! zone anchored by the DS of its KSK.

use std::collections::HashMap;

use dnsy_config::Validation;
use dnsy_dnssec::{Algorithm, DigestType, SigningKey, TrustAnchors, Validator, ds_for};
use dnsy_proto::{RecordType, TypeBitmap};
use dnsy_resolver::CacheLookup;
use dnsy_resolver::forward::{DnssecPolicy, RELEASE_FLOOR_UNIX, unix_now};

use super::*;

/// Seconds since the epoch as the signer sees it.
fn now32() -> u32 {
    u32::try_from(unix_now()).unwrap()
}

struct Zone {
    apex: Name,
    ksk: SigningKey,
    zsk: SigningKey,
}

impl Zone {
    fn new() -> Self {
        Self {
            apex: name("example."),
            ksk: SigningKey::generate(Algorithm::EcdsaP256Sha256, true).unwrap(),
            zsk: SigningKey::generate(Algorithm::EcdsaP256Sha256, false).unwrap(),
        }
    }

    fn sign_until(&self, mut rrset: Vec<Record>, expiration: u32) -> Vec<Record> {
        let key = if rrset[0].rtype == RecordType::Dnskey {
            &self.ksk
        } else {
            &self.zsk
        };
        let sig = key
            .sign_rrset(&rrset, &self.apex, now32() - 3_600, expiration)
            .unwrap();
        rrset.push(sig);
        rrset
    }

    fn sign(&self, rrset: Vec<Record>) -> Vec<Record> {
        self.sign_until(rrset, now32() + 7 * 86_400)
    }

    fn dnskeys(&self) -> Vec<Record> {
        [&self.ksk, &self.zsk]
            .iter()
            .map(|k| Record {
                ttl: 3_600,
                ..rec("example.", RData::Dnskey(k.dnskey()))
            })
            .collect()
    }

    fn anchors(&self) -> TrustAnchors {
        let mut ta = TrustAnchors::new();
        ta.add_ds(
            self.apex.clone(),
            ds_for(&self.apex, &self.ksk.dnskey(), DigestType::Sha256).unwrap(),
        );
        ta
    }
}

fn a(owner: &str) -> Record {
    rec(owner, RData::A(Ipv4Addr::new(192, 0, 2, 1)))
}

fn soa_rec(apex: &str) -> Record {
    rec(
        apex,
        RData::Soa(Soa {
            mname: name(apex),
            rname: name(apex),
            serial: 1,
            refresh: 1,
            retry: 1,
            expire: 1,
            minimum: 300,
        }),
    )
}

fn corrupt(records: &mut [Record]) {
    for r in records {
        if let RData::Rrsig(s) = &mut r.data {
            let last = s.signature.len() - 1;
            s.signature[last] ^= 1;
        }
    }
}

type Sections = (Rcode, Vec<Record>, Vec<Record>);

/// What the upstream knows, and what it was asked.
struct World {
    zone: Zone,
    map: HashMap<(Name, RecordType), Sections>,
}

impl World {
    fn new() -> Self {
        let zone = Zone::new();
        let mut map = HashMap::new();
        let mut serve = |n: &str, t: RecordType, s: Sections| {
            map.insert((name(n), t), s);
        };
        serve(
            "example.",
            RecordType::Dnskey,
            (Rcode::NoError, zone.sign(zone.dnskeys()), vec![]),
        );
        serve(
            "www.example.",
            RecordType::A,
            (Rcode::NoError, zone.sign(vec![a("www.example.")]), vec![]),
        );
        serve(
            "short.example.",
            RecordType::A,
            (
                Rcode::NoError,
                zone.sign_until(vec![a("short.example.")], now32() + 100),
                vec![],
            ),
        );
        let mut bad = zone.sign(vec![a("bad.example.")]);
        corrupt(&mut bad);
        serve("bad.example.", RecordType::A, (Rcode::NoError, bad, vec![]));
        serve(
            "broken.example.",
            RecordType::A,
            (Rcode::NoError, vec![a("broken.example.")], vec![]),
        );
        // insecure.example. is an unsigned delegation, proven by the parent's NSEC.
        let mut auth = zone.sign(vec![rec(
            "insecure.example.",
            RData::Nsec {
                next: name("www.example."),
                types: TypeBitmap::from_types(&[
                    RecordType::Ns,
                    RecordType::Rrsig,
                    RecordType::Nsec,
                ]),
            },
        )]);
        auth.extend(zone.sign(vec![soa_rec("example.")]));
        serve(
            "insecure.example.",
            RecordType::Ds,
            (Rcode::NoError, vec![], auth),
        );
        serve(
            "host.insecure.example.",
            RecordType::Ds,
            (Rcode::NoError, vec![], vec![soa_rec("insecure.example.")]),
        );
        serve(
            "host.insecure.example.",
            RecordType::A,
            (Rcode::NoError, vec![a("host.insecure.example.")], vec![]),
        );
        Self { zone, map }
    }

    fn policy(&self, mode: Validation) -> DnssecPolicy {
        DnssecPolicy {
            mode,
            validator: Validator::new(self.zone.anchors()),
            not_before_unix: RELEASE_FLOOR_UNIX,
        }
    }
}

/// Every query the fake upstream saw: (name, type, DO, CD).
type Seen = Arc<Mutex<Vec<(Name, RecordType, bool, bool)>>>;

struct Rig {
    h: Harness,
    seen: Seen,
}

fn rig_with(policy: impl FnOnce(&World) -> DnssecPolicy) -> Rig {
    let world = World::new();
    let policy = policy(&world);
    let seen: Seen = Arc::default();
    let log = Arc::clone(&seen);
    let fake = Fake::answering(move |q| {
        let question = &q.questions[0];
        log.lock().unwrap().push((
            question.name.clone(),
            question.qtype,
            q.edns.as_ref().is_some_and(|e| e.dnssec_ok),
            q.header.cd,
        ));
        let mut r = Message::response_to(q);
        let Some((rcode, answers, authority)) = world
            .map
            .get(&(question.name.to_lowercase(), question.qtype))
            .cloned()
        else {
            r.header.rcode = Rcode::Refused;
            return Ok(r);
        };
        r.header.rcode = rcode;
        let dnssec_ok = q.edns.as_ref().is_some_and(|e| e.dnssec_ok);
        let keep =
            |r: &Record| dnssec_ok || !matches!(r.rtype, RecordType::Rrsig | RecordType::Nsec);
        r.answers = answers.into_iter().filter(keep).collect();
        r.authority = authority.into_iter().filter(keep).collect();
        Ok(r)
    });
    let h = harness_with(fake, &Config::default(), |b| b.dnssec(policy));
    Rig { h, seen }
}

fn rig(mode: Validation) -> Rig {
    rig_with(|w| w.policy(mode))
}

/// A query with the given DO, AD and CD bits.
fn q(qname: &str, do_bit: bool, ad: bool, cd: bool) -> Message {
    let mut m = query(qname, RecordType::A);
    m.edns = Some(Edns {
        dnssec_ok: do_bit,
        ..Edns::default()
    });
    m.header.ad = ad;
    m.header.cd = cd;
    m
}

impl Rig {
    async fn ask(&self, m: Message) -> Message {
        self.h.engine.handle(ctx(), m).await
    }

    fn statuses(&self) -> Vec<DnssecStatus> {
        self.h.events.take().into_iter().map(|e| e.dnssec).collect()
    }

    fn cached(&self, qname: &str, do_bit: bool, cd: bool) -> Option<(Message, DnssecStatus)> {
        let key = CacheKey {
            name: name(qname),
            qtype: RecordType::A,
            qclass: Class::In,
            do_bit,
            cd_bit: cd,
        };
        match self.h.engine.cache().get_for(&key, Instant::now(), true) {
            CacheLookup::Fresh { msg, dnssec } => Some((msg, dnssec)),
            _ => None,
        }
    }

    fn dnskey_fetches(&self) -> usize {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.1 == RecordType::Dnskey)
            .count()
    }
}

fn has_rrsig(m: &Message) -> bool {
    m.answers.iter().any(|r| r.rtype == RecordType::Rrsig)
}

#[tokio::test]
async fn strict_bogus_servfail_ede6() {
    let r = rig(Validation::Strict);
    let resp = r.ask(q("bad.example.", true, false, false)).await;
    assert_eq!(resp.header.rcode, Rcode::ServFail);
    assert!(resp.answers.is_empty() && !resp.header.ad);
    assert_eq!(ede_codes(&resp), [ede::DNSSEC_BOGUS]);

    // Served again from the cache: still SERVFAIL with the same EDE, no new upstream query.
    let calls = r.h.fake.calls();
    let again = r.ask(q("bad.example.", true, false, false)).await;
    assert_eq!(again.header.rcode, Rcode::ServFail);
    assert_eq!(ede_codes(&again), [ede::DNSSEC_BOGUS]);
    assert_eq!(r.h.fake.calls(), calls);
    assert_eq!(r.statuses(), [DnssecStatus::Bogus, DnssecStatus::Bogus]);
}

#[tokio::test]
async fn permissive_bogus_answered_without_ad() {
    let r = rig(Validation::Permissive);
    for _ in 0..2 {
        let resp = r.ask(q("bad.example.", true, true, false)).await;
        assert_eq!(resp.header.rcode, Rcode::NoError);
        assert!(!resp.header.ad);
        assert!(resp.answers.iter().any(|x| x.rtype == RecordType::A));
        assert_eq!(ede_codes(&resp), [ede::DNSSEC_BOGUS]);
    }
    assert_eq!(r.statuses(), [DnssecStatus::Bogus, DnssecStatus::Bogus]);
}

#[tokio::test]
async fn secure_sets_ad_only_with_do_or_ad() {
    let r = rig(Validation::Strict);
    let plain = r.ask(q("www.example.", false, false, false)).await;
    assert_eq!(plain.header.rcode, Rcode::NoError);
    assert!(!plain.header.ad && !has_rrsig(&plain));

    let ad = r.ask(q("www.example.", false, true, false)).await;
    assert!(ad.header.ad && !has_rrsig(&ad));

    let dnssec_ok = r.ask(q("www.example.", true, false, false)).await;
    assert!(dnssec_ok.header.ad && has_rrsig(&dnssec_ok));
    assert_eq!(ede_codes(&dnssec_ok), Vec::<u16>::new());

    // Validation queries go upstream with DO=1 and CD=1 whatever the client sent.
    assert!(r.seen.lock().unwrap().iter().all(|s| s.2 && s.3));
    assert_eq!(r.dnskey_fetches(), 1, "DNSKEY fetch memoised in the cache");
    assert!(r.statuses().iter().all(|s| *s == DnssecStatus::Secure));
}

#[tokio::test]
async fn cd_bypasses_validation_and_isolated_in_cache() {
    let r = rig(Validation::Strict);
    let cd = r.ask(q("bad.example.", true, true, true)).await;
    assert_eq!(cd.header.rcode, Rcode::NoError);
    assert!(cd.header.cd && !cd.header.ad);
    assert!(has_rrsig(&cd));
    assert_eq!(r.dnskey_fetches(), 0);
    assert_eq!(
        r.cached("bad.example.", true, true).unwrap().1,
        DnssecStatus::Unchecked
    );

    // A validating client never gets the CD=1 entry.
    let validating = r.ask(q("bad.example.", true, false, false)).await;
    assert_eq!(validating.header.rcode, Rcode::ServFail);
    // And the CD=1 client keeps getting the raw data from its own entry.
    let calls = r.h.fake.calls();
    let cd_again = r.ask(q("bad.example.", true, false, true)).await;
    assert_eq!(cd_again.header.rcode, Rcode::NoError);
    assert_eq!(r.h.fake.calls(), calls);
    assert_eq!(
        r.statuses(),
        [
            DnssecStatus::Unchecked,
            DnssecStatus::Bogus,
            DnssecStatus::Unchecked
        ]
    );
}

#[tokio::test]
async fn insecure_zone_no_ad() {
    let r = rig(Validation::Strict);
    let resp = r.ask(q("host.insecure.example.", true, true, false)).await;
    assert_eq!(resp.header.rcode, Rcode::NoError);
    assert_eq!(resp.answers.len(), 1);
    assert!(!resp.header.ad);
    assert_eq!(r.statuses(), [DnssecStatus::Insecure]);
}

#[tokio::test]
async fn bogus_answer_not_cached_as_secure() {
    for mode in [Validation::Strict, Validation::Permissive] {
        let r = rig(mode);
        r.ask(q("bad.example.", false, false, false)).await;
        let (_, status) = r.cached("bad.example.", false, false).unwrap();
        assert_eq!(status, DnssecStatus::Bogus, "{mode:?}");
        let again = r.ask(q("bad.example.", false, true, false)).await;
        assert!(!again.header.ad, "{mode:?}");
    }
}

#[tokio::test]
async fn cached_ttl_capped_by_rrsig_expiration() {
    let r = rig(Validation::Strict);
    let resp = r.ask(q("short.example.", true, false, false)).await;
    assert!(resp.header.ad);
    assert!(
        resp.answers.iter().all(|x| x.ttl <= 100),
        "{:?}",
        resp.answers
    );
    let (cached, status) = r.cached("short.example.", true, false).unwrap();
    assert_eq!(status, DnssecStatus::Secure);
    assert!(cached.answers.iter().all(|x| x.ttl <= 100));
}

#[tokio::test]
async fn nta_returns_insecure() {
    let r = rig(Validation::Strict);
    let resp = r.ask(q("broken.example.", true, false, false)).await;
    assert_eq!(resp.header.rcode, Rcode::ServFail);
    assert_eq!(ede_codes(&resp), [ede::RRSIGS_MISSING]);

    // Added at run time (API): the cache is flushed and the subtree is no longer validated.
    r.h.engine
        .set_negative_trust_anchors(vec![name("broken.example.")]);
    assert_eq!(r.h.engine.cache().stats().entries, 0);
    let resp = r.ask(q("broken.example.", true, true, false)).await;
    assert_eq!(resp.header.rcode, Rcode::NoError);
    assert!(!resp.header.ad);

    // From the configuration.
    let r2 = rig_with(|w| {
        w.policy(Validation::Strict)
            .with_negative_trust_anchors(vec![name("broken.example.")])
    });
    let resp = r2.ask(q("broken.example.", false, false, false)).await;
    assert_eq!(resp.header.rcode, Rcode::NoError);
    assert_eq!(r.statuses(), [DnssecStatus::Bogus, DnssecStatus::Insecure]);
    assert_eq!(r2.statuses(), [DnssecStatus::Insecure]);
}

#[tokio::test]
async fn clock_before_build_time_degrades_to_indeterminate() {
    let r = rig_with(|w| DnssecPolicy {
        not_before_unix: unix_now() + 365 * 86_400,
        ..w.policy(Validation::Strict)
    });
    assert!(r.h.engine.dnssec_clock_untrusted());
    let bad = r.ask(q("bad.example.", true, true, false)).await;
    assert_eq!(bad.header.rcode, Rcode::NoError, "no mass SERVFAIL");
    assert!(!bad.header.ad);
    let good = r.ask(q("www.example.", true, true, false)).await;
    assert!(!good.header.ad);
    assert_eq!(r.dnskey_fetches(), 0);
    assert_eq!(
        r.statuses(),
        [DnssecStatus::Indeterminate, DnssecStatus::Indeterminate]
    );

    // With a plausible clock the flag stays clear.
    let ok = rig(Validation::Strict);
    assert!(!ok.h.engine.dnssec_clock_untrusted());
}

#[tokio::test]
async fn mode_change_flushes_cache() {
    let r = rig(Validation::Strict);
    r.ask(q("www.example.", false, false, false)).await;
    assert!(r.h.engine.cache().stats().entries > 0);
    r.h.engine.set_dnssec_mode(Validation::Strict);
    assert!(
        r.h.engine.cache().stats().entries > 0,
        "same mode keeps the cache"
    );
    r.h.engine.set_dnssec_mode(Validation::Permissive);
    assert_eq!(r.h.engine.cache().stats().entries, 0);
    assert_eq!(r.h.engine.dnssec_mode(), Validation::Permissive);

    // Off: no validation, DO only when the client sent it, no CD upstream.
    r.ask(q("www.example.", true, false, false)).await;
    r.h.engine.set_dnssec_mode(Validation::Off);
    let off = r.ask(q("bad.example.", false, true, false)).await;
    assert_eq!(off.header.rcode, Rcode::NoError);
    assert!(!off.header.ad);
    let last = r.seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!((last.2, last.3), (false, false));
}

#[tokio::test]
async fn validation_status_in_query_event() {
    let r = rig(Validation::Strict);
    r.ask(q("www.example.", false, false, false)).await;
    r.ask(q("host.insecure.example.", false, false, false))
        .await;
    r.ask(q("bad.example.", false, false, false)).await;
    r.ask(q("www.example.", false, false, false)).await;
    r.ask(q("nas.home.test.", false, false, false)).await;
    assert_eq!(
        r.statuses(),
        [
            DnssecStatus::Secure,
            DnssecStatus::Insecure,
            DnssecStatus::Bogus,
            DnssecStatus::Secure,
            DnssecStatus::Unchecked
        ]
    );
}
