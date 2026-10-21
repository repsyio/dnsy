use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;

use dnsy_proto::Soa;

use super::*;

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn key(n: &str, t: RecordType) -> CacheKey {
    CacheKey {
        name: name(n),
        qtype: t,
        qclass: Class::In,
        do_bit: false,
        cd_bit: false,
    }
}

fn cfg() -> CacheOptions {
    CacheOptions {
        min_ttl: 0,
        max_ttl: 86_400,
        serve_stale: ServeStaleOptions {
            enabled: false,
            ..ServeStaleOptions::default()
        },
        prefetch: PrefetchOptions {
            enabled: false,
            ..PrefetchOptions::default()
        },
        ..CacheOptions::default()
    }
}

fn header(rcode: Rcode) -> Header {
    Header {
        id: 1,
        qr: true,
        opcode: dnsy_proto::Opcode::Query,
        aa: false,
        tc: false,
        rd: true,
        ra: true,
        ad: false,
        cd: false,
        rcode,
    }
}

fn a_record(n: &str, ttl: u32) -> Record {
    Record {
        name: name(n),
        rtype: RecordType::A,
        class: Class::In,
        ttl,
        data: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    }
}

fn soa_record(ttl: u32, minimum: u32) -> Record {
    Record {
        name: name("example.com"),
        rtype: RecordType::Soa,
        class: Class::In,
        ttl,
        data: RData::Soa(Soa {
            mname: name("ns.example.com"),
            rname: name("h.example.com"),
            serial: 1,
            refresh: 1,
            retry: 1,
            expire: 1,
            minimum,
        }),
    }
}

fn response(n: &str, t: RecordType, rcode: Rcode) -> Message {
    Message {
        header: header(rcode),
        questions: vec![Question {
            name: name(n),
            qtype: t,
            qclass: Class::In,
        }],
        answers: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        edns: None,
    }
}

fn positive(n: &str, ttl: u32) -> Message {
    let mut m = response(n, RecordType::A, Rcode::NoError);
    m.answers.push(a_record(n, ttl));
    m
}

fn negative(n: &str, t: RecordType, rcode: Rcode, soa_ttl: u32, minimum: u32) -> Message {
    let mut m = response(n, t, rcode);
    m.authority.push(soa_record(soa_ttl, minimum));
    m
}

fn fresh(l: CacheLookup) -> Message {
    match l {
        CacheLookup::Fresh { msg, .. } => msg,
        other => panic!("expected a hit, got {other:?}"),
    }
}

fn secs_later(t: Instant, s: u64) -> Instant {
    t + Duration::from_secs(s)
}

#[test]
fn ttl_decrements_on_serve() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    let k = key("www.example.com", RecordType::A);
    c.insert(
        k.clone(),
        &positive("www.example.com", 300),
        DnssecStatus::Unchecked,
        t0,
    );
    assert_eq!(fresh(c.get(&k, t0)).answers[0].ttl, 300);
    assert_eq!(fresh(c.get(&k, secs_later(t0, 100))).answers[0].ttl, 200);
    assert_eq!(fresh(c.get(&k, secs_later(t0, 299))).answers[0].ttl, 1);
}

#[test]
fn ttl_clamped_to_min_and_max() {
    let c = Cache::new(CacheOptions {
        min_ttl: 60,
        max_ttl: 600,
        ..cfg()
    });
    let t0 = Instant::now();
    let (lo, hi) = (
        key("lo.example.com", RecordType::A),
        key("hi.example.com", RecordType::A),
    );
    c.insert(
        lo.clone(),
        &positive("lo.example.com", 5),
        DnssecStatus::Unchecked,
        t0,
    );
    c.insert(
        hi.clone(),
        &positive("hi.example.com", 99_999),
        DnssecStatus::Unchecked,
        t0,
    );
    assert_eq!(fresh(c.get(&lo, t0)).answers[0].ttl, 60);
    assert_eq!(fresh(c.get(&hi, t0)).answers[0].ttl, 600);
    assert!(matches!(c.get(&lo, secs_later(t0, 61)), CacheLookup::Miss));
}

#[test]
fn lifetime_is_minimum_across_rrsets() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    let k = key("www.example.com", RecordType::A);
    let mut m = positive("www.example.com", 300);
    m.answers.push(a_record("other.example.com", 30));
    c.insert(k.clone(), &m, DnssecStatus::Unchecked, t0);
    assert!(matches!(
        c.get(&k, secs_later(t0, 29)),
        CacheLookup::Fresh { .. }
    ));
    assert!(matches!(c.get(&k, secs_later(t0, 30)), CacheLookup::Miss));
}

#[test]
fn expired_entry_misses() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    let k = key("www.example.com", RecordType::A);
    c.insert(
        k.clone(),
        &positive("www.example.com", 10),
        DnssecStatus::Unchecked,
        t0,
    );
    assert!(matches!(c.get(&k, secs_later(t0, 10)), CacheLookup::Miss));
    let s = c.stats();
    assert_eq!((s.expired, s.misses, s.entries), (1, 1, 0));
}

#[test]
fn zero_ttl_not_cached() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    c.insert(
        key("z.example.com", RecordType::A),
        &positive("z.example.com", 0),
        DnssecStatus::Unchecked,
        t0,
    );
    assert_eq!(c.stats().inserts, 0);
}

#[test]
fn name_is_case_insensitive() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    c.insert(
        key("WWW.Example.COM", RecordType::A),
        &positive("www.example.com", 60),
        DnssecStatus::Unchecked,
        t0,
    );
    assert!(matches!(
        c.get(&key("www.example.com", RecordType::A), t0),
        CacheLookup::Fresh { .. }
    ));
}

#[test]
fn negative_cache_uses_soa_minimum() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    let k = key("nodata.example.com", RecordType::Aaaa);
    c.insert(
        k.clone(),
        &negative(
            "nodata.example.com",
            RecordType::Aaaa,
            Rcode::NoError,
            900,
            120,
        ),
        DnssecStatus::Unchecked,
        t0,
    );
    let m = fresh(c.get(&k, secs_later(t0, 20)));
    assert_eq!(m.authority[0].ttl, 100);
    assert!(matches!(c.get(&k, secs_later(t0, 120)), CacheLookup::Miss));

    // SOA TTL lower than minimum wins; negative_max_ttl caps both.
    let k2 = key("n2.example.com", RecordType::A);
    c.insert(
        k2.clone(),
        &negative("n2.example.com", RecordType::A, Rcode::NoError, 30, 500),
        DnssecStatus::Unchecked,
        t0,
    );
    assert!(matches!(
        c.get(&k2, secs_later(t0, 29)),
        CacheLookup::Fresh { .. }
    ));
    assert!(matches!(c.get(&k2, secs_later(t0, 30)), CacheLookup::Miss));
    let capped = Cache::new(CacheOptions {
        negative_max_ttl: 10,
        ..cfg()
    });
    capped.insert(
        k.clone(),
        &negative(
            "nodata.example.com",
            RecordType::Aaaa,
            Rcode::NoError,
            900,
            900,
        ),
        DnssecStatus::Unchecked,
        t0,
    );
    assert!(matches!(
        capped.get(&k, secs_later(t0, 10)),
        CacheLookup::Miss
    ));
}

#[test]
fn negative_without_soa_not_cached() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    let k = key("x.example.com", RecordType::A);
    c.insert(
        k.clone(),
        &response("x.example.com", RecordType::A, Rcode::NxDomain),
        DnssecStatus::Unchecked,
        t0,
    );
    c.insert(
        k,
        &response("x.example.com", RecordType::A, Rcode::NoError),
        DnssecStatus::Unchecked,
        t0,
    );
    assert_eq!(c.stats().inserts, 0);
}

#[test]
fn nxdomain_answers_other_types() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    let m = negative("gone.example.com", RecordType::A, Rcode::NxDomain, 300, 300);
    c.insert(
        key("gone.example.com", RecordType::A),
        &m,
        DnssecStatus::Unchecked,
        t0,
    );
    let got = fresh(c.get(&key("gone.example.com", RecordType::Txt), t0));
    assert_eq!(got.header.rcode, Rcode::NxDomain);
    assert_eq!(got.questions[0].qtype, RecordType::Txt);
    // A different DO/CD key does not see it.
    let mut other = key("gone.example.com", RecordType::A);
    other.do_bit = true;
    assert!(matches!(c.get(&other, t0), CacheLookup::Miss));
}

#[test]
fn nxdomain_behind_cname_stays_per_type() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    let mut m = negative(
        "alias.example.com",
        RecordType::A,
        Rcode::NxDomain,
        300,
        300,
    );
    m.answers.push(Record {
        name: name("alias.example.com"),
        rtype: RecordType::Cname,
        class: Class::In,
        ttl: 300,
        data: RData::Cname(name("gone.example.com")),
    });
    c.insert(
        key("alias.example.com", RecordType::A),
        &m,
        DnssecStatus::Unchecked,
        t0,
    );
    assert!(matches!(
        c.get(&key("alias.example.com", RecordType::A), t0),
        CacheLookup::Fresh { .. }
    ));
    assert!(matches!(
        c.get(&key("alias.example.com", RecordType::Txt), t0),
        CacheLookup::Miss
    ));
}

#[test]
fn servfail_short_ttl() {
    let c = Cache::new(CacheOptions {
        servfail_ttl: 5,
        ..cfg()
    });
    let t0 = Instant::now();
    let k = key("down.example.com", RecordType::A);
    c.insert(
        k.clone(),
        &response("down.example.com", RecordType::A, Rcode::ServFail),
        DnssecStatus::Unchecked,
        t0,
    );
    assert_eq!(
        fresh(c.get(&k, secs_later(t0, 4))).header.rcode,
        Rcode::ServFail
    );
    assert!(matches!(c.get(&k, secs_later(t0, 5)), CacheLookup::Miss));
}

#[test]
fn other_rcodes_not_cached() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    c.insert(
        key("r.example.com", RecordType::A),
        &response("r.example.com", RecordType::A, Rcode::Refused),
        DnssecStatus::Unchecked,
        t0,
    );
    assert_eq!(c.stats().inserts, 0);
}

#[test]
fn bounded_eviction_counts() {
    let c = Cache::new(CacheOptions {
        max_entries: 4,
        ..cfg()
    });
    let t0 = Instant::now();
    for i in 0..10 {
        let n = format!("h{i}.example.com");
        c.insert(
            key(&n, RecordType::A),
            &positive(&n, 300),
            DnssecStatus::Unchecked,
            t0,
        );
    }
    let s = c.stats();
    assert_eq!(s.entries, 4);
    assert_eq!(s.capacity, 4);
    assert_eq!(s.inserts, 10);
    assert_eq!(s.evictions, 6);
}

#[test]
fn single_slot_cache_replaces_its_entry() {
    let c = Cache::new(CacheOptions {
        max_entries: 1,
        ..cfg()
    });
    let t0 = Instant::now();
    let (a, b) = (
        key("a.example.com", RecordType::A),
        key("b.example.com", RecordType::A),
    );
    c.insert(
        a.clone(),
        &positive("a.example.com", 300),
        DnssecStatus::Unchecked,
        t0,
    );
    c.insert(
        b.clone(),
        &positive("b.example.com", 300),
        DnssecStatus::Unchecked,
        t0,
    );
    assert!(matches!(c.get(&a, t0), CacheLookup::Miss));
    assert!(matches!(c.get(&b, t0), CacheLookup::Fresh { .. }));
}

#[test]
fn eviction_keeps_recently_used() {
    let c = Cache::new(CacheOptions {
        max_entries: 32,
        ..cfg()
    });
    let t0 = Instant::now();
    let hot = key("hot.example.com", RecordType::A);
    c.insert(
        hot.clone(),
        &positive("hot.example.com", 300),
        DnssecStatus::Unchecked,
        t0,
    );
    for i in 0..200 {
        assert!(
            matches!(c.get(&hot, t0), CacheLookup::Fresh { .. }),
            "hot entry evicted"
        );
        let n = format!("n{i}.example.com");
        c.insert(
            key(&n, RecordType::A),
            &positive(&n, 300),
            DnssecStatus::Unchecked,
            t0,
        );
    }
    assert_eq!(c.stats().entries, 32);
}

#[test]
fn do_bit_separates_entries() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    let plain = key("www.example.com", RecordType::A);
    let mut dok = plain.clone();
    dok.do_bit = true;
    c.insert(
        dok.clone(),
        &positive("www.example.com", 60),
        DnssecStatus::Secure,
        t0,
    );
    assert!(matches!(c.get(&plain, t0), CacheLookup::Miss));
    assert!(matches!(
        c.get(&dok, t0),
        CacheLookup::Fresh {
            dnssec: DnssecStatus::Secure,
            ..
        }
    ));
}

#[test]
fn cd_entries_isolated() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    let normal = key("www.example.com", RecordType::A);
    let mut cd = normal.clone();
    cd.cd_bit = true;
    c.insert(
        cd.clone(),
        &positive("www.example.com", 60),
        DnssecStatus::Unchecked,
        t0,
    );
    assert!(matches!(c.get(&normal, t0), CacheLookup::Miss));
    assert!(matches!(c.get(&cd, t0), CacheLookup::Fresh { .. }));
    // And the other way round.
    let other = key("o.example.com", RecordType::A);
    let mut other_cd = other.clone();
    other_cd.cd_bit = true;
    c.insert(
        other.clone(),
        &positive("o.example.com", 60),
        DnssecStatus::Secure,
        t0,
    );
    assert!(matches!(c.get(&other_cd, t0), CacheLookup::Miss));
}

#[test]
fn bogus_never_served_as_secure() {
    let c = Cache::new(CacheOptions {
        bogus_ttl: 60,
        ..cfg()
    });
    let t0 = Instant::now();
    let k = key("bad.example.com", RecordType::A);
    let mut m = positive("bad.example.com", 3600);
    m.header.ad = true;
    c.insert(k.clone(), &m, DnssecStatus::Bogus, t0);
    let CacheLookup::Fresh { msg, dnssec } = c.get(&k, t0) else {
        panic!("expected entry");
    };
    assert_eq!(dnssec, DnssecStatus::Bogus);
    assert_eq!(msg.header.rcode, Rcode::ServFail);
    assert!(msg.answers.is_empty() && !msg.header.ad);
    // Capped at bogus_ttl.
    assert!(matches!(c.get(&k, secs_later(t0, 60)), CacheLookup::Miss));
}

#[test]
fn bogus_keeps_its_ede_and_is_data_only_when_asked() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    let k = key("bad.example.com", RecordType::A);
    let mut m = positive("bad.example.com", 300);
    m.set_ede(7, "signature expired");
    c.insert(k.clone(), &m, DnssecStatus::Bogus, t0);
    let CacheLookup::Fresh { msg, .. } = c.get(&k, t0) else {
        panic!("expected entry");
    };
    assert_eq!(msg.header.rcode, Rcode::ServFail);
    let opts = msg.edns.unwrap().options;
    assert!(matches!(
        opts[..],
        [EdnsOption::ExtendedError { code: 7, .. }]
    ));
    let CacheLookup::Fresh { msg, dnssec } = c.get_for(&k, t0, true) else {
        panic!("expected entry");
    };
    assert_eq!(dnssec, DnssecStatus::Bogus);
    assert_eq!(msg.header.rcode, Rcode::NoError);
    assert_eq!(msg.answers.len(), 1);
}

#[test]
fn secure_not_overwritten_by_bogus() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    let k = key("www.example.com", RecordType::A);
    c.insert(
        k.clone(),
        &positive("www.example.com", 300),
        DnssecStatus::Secure,
        t0,
    );
    c.insert(
        k.clone(),
        &positive("www.example.com", 300),
        DnssecStatus::Bogus,
        secs_later(t0, 1),
    );
    let CacheLookup::Fresh { msg, dnssec } = c.get(&k, secs_later(t0, 2)) else {
        panic!("expected entry");
    };
    assert_eq!(dnssec, DnssecStatus::Secure);
    assert_eq!(msg.header.rcode, Rcode::NoError);
    // Once the Secure entry has expired, Bogus may take its place.
    c.insert(
        k.clone(),
        &positive("www.example.com", 300),
        DnssecStatus::Bogus,
        secs_later(t0, 400),
    );
    assert!(matches!(
        c.get(&k, secs_later(t0, 401)),
        CacheLookup::Fresh {
            dnssec: DnssecStatus::Bogus,
            ..
        }
    ));
}

#[test]
fn tc_and_aa_not_cached() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    let k = key("www.example.com", RecordType::A);
    let mut tc = positive("www.example.com", 60);
    tc.header.tc = true;
    let mut aa = positive("www.example.com", 60);
    aa.header.aa = true;
    c.insert(k.clone(), &tc, DnssecStatus::Unchecked, t0);
    c.insert(k.clone(), &aa, DnssecStatus::Unchecked, t0);
    assert!(matches!(c.get(&k, t0), CacheLookup::Miss));
    assert_eq!(c.stats().inserts, 0);
}

#[test]
fn disabled_cache_stores_nothing() {
    let c = Cache::new(CacheOptions {
        enabled: false,
        ..cfg()
    });
    let t0 = Instant::now();
    let k = key("www.example.com", RecordType::A);
    c.insert(
        k.clone(),
        &positive("www.example.com", 60),
        DnssecStatus::Unchecked,
        t0,
    );
    assert!(matches!(c.get(&k, t0), CacheLookup::Miss));
}

#[test]
fn flush_name_subtree() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    for n in [
        "example.com",
        "www.example.com",
        "a.b.example.com",
        "example.org",
    ] {
        c.insert(
            key(n, RecordType::A),
            &positive(n, 60),
            DnssecStatus::Unchecked,
            t0,
        );
    }
    assert_eq!(c.flush_name(&name("www.example.com"), false), 1);
    assert_eq!(c.stats().entries, 3);
    assert_eq!(c.flush_name(&name("EXAMPLE.com"), true), 2);
    assert!(matches!(
        c.get(&key("example.org", RecordType::A), t0),
        CacheLookup::Fresh { .. }
    ));
    assert_eq!(c.flush_all(), 1);
    assert_eq!(c.stats().entries, 0);
}

#[test]
fn stats_counters_accurate() {
    let c = Cache::new(CacheOptions {
        max_entries: 100,
        ..cfg()
    });
    let t0 = Instant::now();
    let k = key("www.example.com", RecordType::A);
    assert!(matches!(c.get(&k, t0), CacheLookup::Miss));
    c.insert(
        k.clone(),
        &positive("www.example.com", 60),
        DnssecStatus::Unchecked,
        t0,
    );
    c.get(&k, t0);
    c.get(&k, t0);
    let s = c.stats();
    assert_eq!(
        (
            s.entries,
            s.capacity,
            s.hits,
            s.misses,
            s.inserts,
            s.evictions,
            s.expired
        ),
        (1, 100, 2, 1, 1, 0, 0)
    );
    assert_eq!((s.stale_served, s.prefetches), (0, 0));
}

#[test]
fn concurrent_get_insert() {
    let c = Arc::new(Cache::new(CacheOptions {
        max_entries: 64,
        ..cfg()
    }));
    let t0 = Instant::now();
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let c = Arc::clone(&c);
            thread::spawn(move || {
                for i in 0..500 {
                    let n = format!("h{}.example.com", (i * 7 + t) % 100);
                    let k = key(&n, RecordType::A);
                    c.insert(k.clone(), &positive(&n, 300), DnssecStatus::Unchecked, t0);
                    if let CacheLookup::Fresh { msg, .. } = c.get(&k, t0) {
                        assert_eq!(msg.answers[0].name, name(&n));
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let s = c.stats();
    assert!(s.entries <= 64);
    assert_eq!(s.inserts, 8 * 500);
    assert_eq!(s.hits + s.misses, 8 * 500);
}

#[test]
fn qtype_zero_neither_hits_nor_overwrites_name_level_nxdomain() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    let zero = RecordType::Unknown(0);
    let m = negative("gone.example.com", RecordType::A, Rcode::NxDomain, 300, 300);
    c.insert(
        key("gone.example.com", RecordType::A),
        &m,
        DnssecStatus::Unchecked,
        t0,
    );
    // A type-0 query does not read the name-level entry.
    assert!(matches!(
        c.get(&key("gone.example.com", zero), t0),
        CacheLookup::Miss
    ));
    // A type-0 response is not cached, so it cannot replace it either.
    c.insert(
        key("gone.example.com", zero),
        &positive("gone.example.com", 300),
        DnssecStatus::Unchecked,
        t0,
    );
    let got = fresh(c.get(&key("gone.example.com", RecordType::Txt), t0));
    assert_eq!(got.header.rcode, Rcode::NxDomain);
    assert_eq!(got.questions[0].qtype, RecordType::Txt);
    assert_eq!(c.stats().inserts, 1);
}

#[test]
fn bound_is_global_whatever_the_hash_distribution() {
    // Each new cache hashes differently. With a per-shard bound, a shard that received no keys
    // left the cache under-filled (entries < max_entries); the bound must be global.
    for _ in 0..300 {
        let c = Cache::new(CacheOptions {
            max_entries: 4,
            ..cfg()
        });
        let t0 = Instant::now();
        for i in 0..10 {
            let n = format!("h{i}.example.com");
            c.insert(
                key(&n, RecordType::A),
                &positive(&n, 300),
                DnssecStatus::Unchecked,
                t0,
            );
        }
        let s = c.stats();
        assert_eq!((s.entries, s.inserts, s.evictions), (4, 10, 6));
    }
}

#[test]
fn reconfigure_changes_ttl_bounds_for_later_inserts() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    let k = key("www.example.com", RecordType::A);
    c.insert(
        k.clone(),
        &positive("www.example.com", 300),
        DnssecStatus::Unchecked,
        t0,
    );
    assert_eq!(fresh(c.get(&k, t0)).answers[0].ttl, 300);
    c.reconfigure(|cfg| cfg.max_ttl = 60);
    c.insert(
        k.clone(),
        &positive("www.example.com", 300),
        DnssecStatus::Unchecked,
        t0,
    );
    assert_eq!(fresh(c.get(&k, t0)).answers[0].ttl, 60);
}

fn stale_cfg() -> CacheOptions {
    CacheOptions {
        serve_stale: ServeStaleOptions {
            enabled: true,
            max_stale: 1000,
            answer_ttl: 30,
            client_timeout_ms: 1800,
        },
        ..cfg()
    }
}

fn stale(l: CacheLookup) -> (Message, DnssecStatus, Duration) {
    match l {
        CacheLookup::Stale {
            msg,
            dnssec,
            stale_for,
        } => (msg, dnssec, stale_for),
        other => panic!("expected stale, got {other:?}"),
    }
}

#[test]
fn stale_window_follows_expiry() {
    let c = Cache::new(stale_cfg());
    let t0 = Instant::now();
    let k = key("www.example.com", RecordType::A);
    c.insert(
        k.clone(),
        &positive("www.example.com", 100),
        DnssecStatus::Unchecked,
        t0,
    );
    let (msg, status, age) = stale(c.get(&k, secs_later(t0, 150)));
    assert_eq!(
        (msg.answers[0].ttl, status, age),
        (30, DnssecStatus::Unchecked, Duration::from_secs(50))
    );
    assert_eq!(c.stats().entries, 1);
    // Past max_stale the entry is gone.
    assert_eq!(c.get(&k, secs_later(t0, 1100)), CacheLookup::Miss);
    assert_eq!(c.stats().entries, 0);
}

#[test]
fn stale_disabled_expires_normally() {
    let c = Cache::new(cfg());
    let t0 = Instant::now();
    let k = key("www.example.com", RecordType::A);
    c.insert(
        k.clone(),
        &positive("www.example.com", 100),
        DnssecStatus::Unchecked,
        t0,
    );
    assert_eq!(c.get(&k, secs_later(t0, 101)), CacheLookup::Miss);
}

#[test]
fn stale_nxdomain_answers_other_types_by_name() {
    let c = Cache::new(stale_cfg());
    let t0 = Instant::now();
    c.insert(
        key("gone.example.com", RecordType::A),
        &negative("gone.example.com", RecordType::A, Rcode::NxDomain, 60, 60),
        DnssecStatus::Unchecked,
        t0,
    );
    let (m, _, _) = stale(c.get(
        &key("gone.example.com", RecordType::Aaaa),
        secs_later(t0, 90),
    ));
    assert_eq!(m.header.rcode, Rcode::NxDomain);
    assert_eq!(m.questions[0].qtype, RecordType::Aaaa);
    assert_eq!(m.authority[0].ttl, 30);
}

#[test]
fn stale_bogus_and_servfail_never_served() {
    let c = Cache::new(stale_cfg());
    let t0 = Instant::now();
    let (bogus, sf) = (
        key("bad.example.com", RecordType::A),
        key("sf.example.com", RecordType::A),
    );
    c.insert(
        bogus.clone(),
        &positive("bad.example.com", 100),
        DnssecStatus::Bogus,
        t0,
    );
    c.insert(
        sf.clone(),
        &response("sf.example.com", RecordType::A, Rcode::ServFail),
        DnssecStatus::Unchecked,
        t0,
    );
    let later = secs_later(t0, 200);
    assert_eq!(c.get(&bogus, later), CacheLookup::Miss);
    assert_eq!(c.get(&sf, later), CacheLookup::Miss);
}

#[test]
fn stale_secure_is_not_reported_validated() {
    let c = Cache::new(stale_cfg());
    let t0 = Instant::now();
    let k = key("s.example.com", RecordType::A);
    c.insert(
        k.clone(),
        &positive("s.example.com", 100),
        DnssecStatus::Secure,
        t0,
    );
    assert_eq!(fresh(c.get(&k, t0)).answers.len(), 1);
    let (_, d, _) = stale(c.get(&k, secs_later(t0, 101)));
    assert_eq!(d, DnssecStatus::Indeterminate);
}

#[test]
fn refresh_replaces_stale() {
    let c = Cache::new(stale_cfg());
    let t0 = Instant::now();
    let k = key("www.example.com", RecordType::A);
    c.insert(
        k.clone(),
        &positive("www.example.com", 100),
        DnssecStatus::Unchecked,
        t0,
    );
    let t1 = secs_later(t0, 150);
    stale(c.get(&k, t1));
    c.insert(
        k.clone(),
        &positive("www.example.com", 300),
        DnssecStatus::Unchecked,
        t1,
    );
    assert_eq!(fresh(c.get(&k, t1)).answers[0].ttl, 300);
    assert_eq!(c.stats().entries, 1);
}

#[test]
fn stale_entries_stay_within_the_bound() {
    let c = Cache::new(CacheOptions {
        max_entries: 4,
        ..stale_cfg()
    });
    let t0 = Instant::now();
    for i in 0..20 {
        let n = format!("h{i}.example.com");
        c.insert(
            key(&n, RecordType::A),
            &positive(&n, 10),
            DnssecStatus::Unchecked,
            t0,
        );
    }
    assert!(c.stats().entries <= 4);
}

#[test]
fn refreshes_coalesce_per_key() {
    let r = Refreshes::<()>::new();
    let (a, b) = (
        key("a.example.com", RecordType::A),
        key("b.example.com", RecordType::A),
    );
    let g = r.begin(&a).unwrap();
    assert!(r.begin(&a).is_none());
    assert!(r.begin(&b).is_some());
    assert_eq!(r.len(), 1);
    drop(g);
    assert!(r.is_empty());
    assert!(r.begin(&a).is_some());
}

#[tokio::test]
async fn joined_waiters_get_the_leaders_result() {
    let r = Refreshes::<u32>::new();
    let k = key("a.example.com", RecordType::A);
    let Joined::Leader(lead) = r.join(&k, 2) else {
        panic!("first caller leads")
    };
    let Joined::Waiter(w1) = r.join(&k, 2) else {
        panic!("second caller waits")
    };
    assert!(r.begin(&k).is_none(), "begin sees the flight too");
    let Joined::Waiter(w2) = r.join(&k, 2) else {
        panic!("third caller waits")
    };
    assert!(matches!(r.join(&k, 2), Joined::Busy), "waiters are bounded");
    lead.finish(|| 7);
    assert!(r.is_empty(), "finishing frees the slot at once");
    assert_eq!((w1.wait().await, w2.wait().await), (Some(7), Some(7)));
    assert!(matches!(r.join(&k, 2), Joined::Leader(_)));
}

#[tokio::test]
async fn waiters_of_a_dropped_leader_see_none() {
    let r = Refreshes::<u32>::new();
    let k = key("a.example.com", RecordType::A);
    let lead = r.begin(&k).unwrap();
    let Joined::Waiter(w) = r.join(&k, 1) else {
        panic!("waits")
    };
    drop(lead);
    assert_eq!(w.wait().await, None);
    assert!(r.is_empty());
}

#[tokio::test]
async fn waiter_slots_are_released_on_drop() {
    let r = Refreshes::<u32>::new();
    let k = key("a.example.com", RecordType::A);
    let _lead = r.begin(&k).unwrap();
    let w = r.join(&k, 1);
    assert!(matches!(r.join(&k, 1), Joined::Busy));
    drop(w);
    assert!(matches!(r.join(&k, 1), Joined::Waiter(_)));
}

#[tokio::test]
async fn finishing_without_waiters_skips_the_value() {
    let r = Refreshes::<u32>::new();
    let k = key("a.example.com", RecordType::A);
    let first = r.begin(&k).unwrap();
    first.finish(|| panic!("nobody waits, nothing to build"));
    assert!(r.is_empty());
    assert!(r.begin(&k).is_some());
}

fn prefetch_cfg() -> CacheOptions {
    CacheOptions {
        prefetch: PrefetchOptions {
            enabled: true,
            min_hits: 3,
            remaining_ttl_pct: 10,
        },
        ..cfg()
    }
}

#[test]
fn prefetch_triggers_for_popular_entry_once() {
    let c = Cache::new(prefetch_cfg());
    let t0 = Instant::now();
    let k = key("www.example.com", RecordType::A);
    c.insert(
        k.clone(),
        &positive("www.example.com", 100),
        DnssecStatus::Unchecked,
        t0,
    );
    for _ in 0..3 {
        fresh(c.get(&k, t0));
    }
    assert!(
        !c.prefetch_due(&k, secs_later(t0, 50)),
        "plenty of TTL left"
    );
    let late = secs_later(t0, 92);
    fresh(c.get(&k, late));
    assert!(c.prefetch_due(&k, late));
    assert!(!c.prefetch_due(&k, late), "only once per entry");
    // A refresh is a new entry and can be prefetched again once popular.
    c.insert(
        k.clone(),
        &positive("www.example.com", 100),
        DnssecStatus::Unchecked,
        late,
    );
    assert!(!c.prefetch_due(&k, secs_later(late, 95)));
}

#[test]
fn prefetch_not_triggered_below_min_hits() {
    let c = Cache::new(prefetch_cfg());
    let t0 = Instant::now();
    let k = key("www.example.com", RecordType::A);
    c.insert(
        k.clone(),
        &positive("www.example.com", 100),
        DnssecStatus::Unchecked,
        t0,
    );
    fresh(c.get(&k, t0));
    fresh(c.get(&k, t0));
    assert!(!c.prefetch_due(&k, secs_later(t0, 95)));
}

#[test]
fn prefetch_disabled_and_bogus_and_expired_never_due() {
    let t0 = Instant::now();
    let k = key("www.example.com", RecordType::A);
    let off = Cache::new(cfg());
    off.insert(
        k.clone(),
        &positive("www.example.com", 100),
        DnssecStatus::Unchecked,
        t0,
    );
    for _ in 0..10 {
        fresh(off.get(&k, t0));
    }
    assert!(!off.prefetch_due(&k, secs_later(t0, 95)));

    let c = Cache::new(prefetch_cfg());
    c.insert(
        k.clone(),
        &positive("www.example.com", 100),
        DnssecStatus::Unchecked,
        t0,
    );
    for _ in 0..5 {
        fresh(c.get(&k, t0));
    }
    assert!(!c.prefetch_due(&k, secs_later(t0, 100)), "expired");
    assert!(!c.prefetch_due(&key("none.example.com", RecordType::A), t0));
    let bogus = key("bad.example.com", RecordType::A);
    c.insert(
        bogus.clone(),
        &positive("bad.example.com", 100),
        DnssecStatus::Bogus,
        t0,
    );
    assert!(!c.prefetch_due(&bogus, secs_later(t0, 95)));
}

#[test]
fn stale_and_prefetch_counters() {
    let c = Cache::new(cfg());
    c.note_stale_served();
    c.note_prefetch();
    c.note_prefetch();
    let s = c.stats();
    assert_eq!((s.stale_served, s.prefetches), (1, 2));
}
