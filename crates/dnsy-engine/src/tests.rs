use std::future::pending;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dnsy_config::Config;
use dnsy_core::{DnssecStatus, Principal, TokenId, Transport, UserId};
use dnsy_filter::{Acl, AclAction, AclMatcher, BlockMode, FilterLimits, FilterSetBuilder};
use dnsy_observe::{AnswerSource, QueryEvent, QueryEventSink};
use dnsy_proto::{
    Class, Edns, EdnsOption, Header, Message, Name, Opcode, Question, RData, Rcode, Record,
    RecordType, Soa, ede,
};
use dnsy_resolver::groups::{
    Exchange, GroupMember, GroupSet, GroupSpec, Strategy, SystemClock, ThreadRng,
};
use dnsy_resolver::{CacheKey, Upstream, UpstreamError};
use dnsy_store::Store;
use dnsy_zone::ZoneStore;
use tempfile::TempDir;

use crate::{Engine, EngineBuilder, Handler, RESPONSE_IP_LIST, RequestContext, ResponseIpPolicy};

const ZONE: &str = r#"{"schema":1,"origin":"home.test.","default_ttl":3600,
  "soa":{"mname":"ns.home.test.","rname":"h.home.test.","serial":1,"refresh":1,"retry":1,
         "expire":1,"minimum":300},
  "records":[
    {"name":"@","type":"NS","value":"ns.home.test."},
    {"name":"ns","type":"A","value":"192.0.2.53"},
    {"name":"nas","type":"A","value":"192.0.2.10"},
    {"name":"dangling","type":"CNAME","value":"missing.home.test."},
    {"name":"to-nodata","type":"CNAME","value":"nas.home.test."}
  ]}"#;

type Answer = Box<dyn Fn(&Message) -> Result<Message, UpstreamError> + Send + Sync>;

/// A scripted upstream.
struct Fake {
    calls: AtomicUsize,
    hang: bool,
    answer: Answer,
}

impl Fake {
    fn answering(
        answer: impl Fn(&Message) -> Result<Message, UpstreamError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            hang: false,
            answer: Box::new(answer),
        }
    }

    fn a_record(ip: Ipv4Addr) -> Self {
        Self::answering(move |q| {
            let mut r = Message::response_to(q);
            r.answers
                .push(rec(&q.questions[0].name.to_string(), RData::A(ip)));
            Ok(r)
        })
    }

    fn hanging() -> Self {
        Self {
            hang: true,
            ..Self::answering(|_| Err(UpstreamError::Timeout))
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

/// Shares a [`Fake`] between the engine and the test.
struct Up(Arc<Fake>);

impl Exchange for Up {
    async fn exchange(
        &self,
        _upstream: &Upstream,
        query: &Message,
    ) -> Result<Message, UpstreamError> {
        let fake = &self.0;
        fake.calls.fetch_add(1, Ordering::SeqCst);
        if fake.hang {
            pending::<()>().await;
        }
        (fake.answer)(query)
    }
}

#[derive(Default)]
struct Events(Mutex<Vec<QueryEvent>>);

impl QueryEventSink for Events {
    fn record(&self, ev: QueryEvent) {
        self.0.lock().unwrap().push(ev);
    }
}

impl Events {
    fn take(&self) -> Vec<QueryEvent> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn rec(owner: &str, data: RData) -> Record {
    Record {
        name: name(owner),
        rtype: data.rtype(),
        class: Class::In,
        ttl: 300,
        data,
    }
}

fn query(qname: &str, qtype: RecordType) -> Message {
    Message {
        header: Header {
            id: 0xbeef,
            qr: false,
            opcode: Opcode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            ad: false,
            cd: false,
            rcode: Rcode::NoError,
        },
        questions: vec![Question {
            name: name(qname),
            qtype,
            qclass: Class::In,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
        edns: Some(Edns::default()),
    }
}

fn ctx() -> RequestContext {
    RequestContext {
        client: ([192, 0, 2, 200], 40000).into(),
        transport: Transport::Udp,
        principal: None,
        received_at: Instant::now(),
    }
}

fn groups() -> GroupSet {
    GroupSet::new(
        vec![GroupSpec {
            name: "default".to_owned(),
            strategy: Strategy::Failover,
            default: true,
            domains: vec![],
            members: vec![GroupMember {
                upstream: "udp://192.0.2.1:53".parse().unwrap(),
                weight: 1,
            }],
        }],
        Arc::new(SystemClock::new()),
        Arc::new(ThreadRng),
    )
    .unwrap()
}

fn zones() -> (TempDir, Arc<ZoneStore>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("home.test.json"), ZONE).unwrap();
    let store = ZoneStore::open(dir.path()).unwrap();
    (dir, store)
}

struct Harness {
    engine: Engine<Up>,
    fake: Arc<Fake>,
    events: Arc<Events>,
    _zones: TempDir,
}

fn harness_with(
    fake: Fake,
    config: &Config,
    f: impl FnOnce(EngineBuilder<Up>) -> EngineBuilder<Up>,
) -> Harness {
    let fake = Arc::new(fake);
    let events = Arc::new(Events::default());
    let (dir, zone_store) = zones();
    let builder = EngineBuilder::new(config, Up(Arc::clone(&fake)))
        .zones(zone_store)
        .groups(groups())
        .sink(Arc::clone(&events) as Arc<dyn QueryEventSink>);
    Harness {
        engine: f(builder).build(),
        fake,
        events,
        _zones: dir,
    }
}

fn harness(fake: Fake) -> Harness {
    harness_with(fake, &Config::default(), |b| b)
}

fn ede_codes(msg: &Message) -> Vec<u16> {
    msg.edns
        .iter()
        .flat_map(|e| &e.options)
        .filter_map(|o| match o {
            EdnsOption::ExtendedError { code, .. } => Some(*code),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn local_zone_answers_aa() {
    let h = harness(Fake::a_record(Ipv4Addr::LOCALHOST));
    let r = h
        .engine
        .handle(ctx(), query("NAS.home.test.", RecordType::A))
        .await;
    assert!(r.header.aa && r.header.qr && r.header.ra);
    assert_eq!(r.header.id, 0xbeef);
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert_eq!(r.answers.len(), 1);
    assert_eq!(r.answers[0].data, RData::A(Ipv4Addr::new(192, 0, 2, 10)));
    assert_eq!(r.questions[0].name.to_string(), "NAS.home.test.");
    assert_eq!(h.fake.calls(), 0);

    let nx = h
        .engine
        .handle(ctx(), query("nope.home.test.", RecordType::A))
        .await;
    assert_eq!(nx.header.rcode, Rcode::NxDomain);
    assert!(nx.header.aa);
    assert_eq!(nx.authority[0].rtype, RecordType::Soa);
}

#[tokio::test]
async fn cname_to_missing_name_is_nxdomain_rfc6604() {
    let h = harness(Fake::a_record(Ipv4Addr::LOCALHOST));
    let r = h
        .engine
        .handle(ctx(), query("dangling.home.test.", RecordType::A))
        .await;
    assert_eq!(r.header.rcode, Rcode::NxDomain);
    assert_eq!(r.answers[0].rtype, RecordType::Cname);
    assert!(r.authority.iter().any(|a| a.rtype == RecordType::Soa));

    let r = h
        .engine
        .handle(ctx(), query("to-nodata.home.test.", RecordType::Aaaa))
        .await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert_eq!(r.answers[0].rtype, RecordType::Cname);
}

#[tokio::test]
async fn authoritative_answers_not_cached() {
    let h = harness(Fake::a_record(Ipv4Addr::LOCALHOST));
    // A stale-looking cache entry for a local name must never be consulted...
    let mut planted = Message::response_to(&query("nas.home.test.", RecordType::A));
    planted.answers.push(rec(
        "nas.home.test.",
        RData::A(Ipv4Addr::new(203, 0, 113, 66)),
    ));
    let key = CacheKey {
        name: name("nas.home.test."),
        qtype: RecordType::A,
        qclass: Class::In,
        do_bit: false,
        cd_bit: false,
    };
    h.engine
        .cache()
        .insert(key, &planted, DnssecStatus::Unchecked, Instant::now());
    let inserts = h.engine.cache().stats().inserts;
    let r = h
        .engine
        .handle(ctx(), query("nas.home.test.", RecordType::A))
        .await;
    assert_eq!(r.answers[0].data, RData::A(Ipv4Addr::new(192, 0, 2, 10)));
    // ...and authoritative answers are never inserted.
    h.engine
        .handle(ctx(), query("nope.home.test.", RecordType::A))
        .await;
    let stats = h.engine.cache().stats();
    assert_eq!(stats.inserts, inserts);
    assert_eq!(stats.hits + stats.misses, 0);
}

#[tokio::test]
async fn blocked_returns_nxdomain_with_ede() {
    let mut fb = FilterSetBuilder::new(BlockMode::NxDomain, FilterLimits::default());
    fb.add_block_rule("ads.example").unwrap();
    let mut lists = FilterSetBuilder::new(BlockMode::NxDomain, FilterLimits::default());
    lists
        .add_list(
            "easylist",
            dnsy_filter::ListFormat::Domains,
            "tracker.example\n".as_bytes(),
        )
        .unwrap();
    let h = harness_with(
        Fake::a_record(Ipv4Addr::LOCALHOST),
        &Config::default(),
        |b| b.filter(lists.build()),
    );
    let r = h
        .engine
        .handle(ctx(), query("x.tracker.example.", RecordType::A))
        .await;
    assert_eq!(r.header.rcode, Rcode::NxDomain);
    assert_eq!(ede_codes(&r), [ede::BLOCKED]);
    assert_eq!(h.fake.calls(), 0);
    let ev = h.events.take();
    assert_eq!(
        ev[0].source,
        AnswerSource::Blocked {
            list: "easylist".to_owned()
        }
    );

    let h = harness_with(
        Fake::a_record(Ipv4Addr::LOCALHOST),
        &Config::default(),
        |b| b.filter(fb.build()),
    );
    assert!(h.engine.list_manager().is_none());
    let r = h
        .engine
        .handle(ctx(), query("ads.example.", RecordType::A))
        .await;
    assert_eq!(ede_codes(&r), [ede::FILTERED]);
}

#[tokio::test]
async fn blocked_not_cached() {
    let mut fb = FilterSetBuilder::new(BlockMode::NullIp, FilterLimits::default());
    fb.add_block_rule("ads.example").unwrap();
    let h = harness_with(
        Fake::a_record(Ipv4Addr::LOCALHOST),
        &Config::default(),
        |b| b.filter(fb.build()),
    );
    let r = h
        .engine
        .handle(ctx(), query("ads.example.", RecordType::A))
        .await;
    assert_eq!(r.answers[0].data, RData::A(Ipv4Addr::UNSPECIFIED));
    let stats = h.engine.cache().stats();
    assert_eq!(
        (stats.inserts, stats.entries, stats.hits + stats.misses),
        (0, 0, 0)
    );
}

#[tokio::test]
async fn cache_hit_skips_upstream() {
    let h = harness(Fake::a_record(Ipv4Addr::new(192, 0, 2, 7)));
    let first = h
        .engine
        .handle(ctx(), query("www.example.", RecordType::A))
        .await;
    assert_eq!(first.answers[0].data, RData::A(Ipv4Addr::new(192, 0, 2, 7)));
    assert!(!first.header.aa);
    let mut q = query("WWW.example.", RecordType::A);
    q.header.id = 7;
    let second = h.engine.handle(ctx(), q).await;
    assert_eq!(second.header.id, 7);
    assert_eq!(second.questions[0].name.to_string(), "WWW.example.");
    assert_eq!(second.answers, first.answers);
    assert_eq!(h.fake.calls(), 1);
    let ev = h.events.take();
    assert!(
        matches!(ev[0].source, AnswerSource::Upstream(a) if a == SocketAddr::from(([192, 0, 2, 1], 53)))
    );
    assert_eq!(ev[1].source, AnswerSource::Cache);

    // The DO and CD bits select separate cache entries.
    let mut cd = query("www.example.", RecordType::A);
    cd.header.cd = true;
    h.engine.handle(ctx(), cd).await;
    let mut d = query("www.example.", RecordType::A);
    d.edns.as_mut().unwrap().dnssec_ok = true;
    let r = h.engine.handle(ctx(), d).await;
    assert!(r.edns.unwrap().dnssec_ok);
    assert_eq!(h.fake.calls(), 3);
}

#[tokio::test]
async fn all_upstreams_down_servfail_with_ede_within_deadline() {
    let mut config = Config::default();
    config.resolver.timeout_ms = 100;
    config.resolver.attempts = 2;
    let h = harness_with(Fake::hanging(), &config, |b| b);
    let started = Instant::now();
    let r = h
        .engine
        .handle(ctx(), query("www.example.", RecordType::A))
        .await;
    let took = started.elapsed();
    assert_eq!(r.header.rcode, Rcode::ServFail);
    assert_eq!(ede_codes(&r), [ede::NO_REACHABLE_AUTHORITY]);
    assert!(
        took >= Duration::from_millis(190) && took < Duration::from_millis(1000),
        "{took:?}"
    );
    assert_eq!(h.events.take()[0].source, AnswerSource::Error);
    assert_eq!(h.engine.cache().stats().inserts, 0);
}

#[tokio::test]
async fn upstream_network_error_servfail_ede23() {
    let h = harness(Fake::answering(|_| Err(UpstreamError::Mismatch)));
    let r = h
        .engine
        .handle(ctx(), query("www.example.", RecordType::A))
        .await;
    assert_eq!(r.header.rcode, Rcode::ServFail);
    assert_eq!(ede_codes(&r), [ede::NETWORK_ERROR]);
    // `attempts` (default 2) tries.
    assert_eq!(h.fake.calls(), 2);
}

#[tokio::test]
async fn no_upstreams_servfail_ede22() {
    let fake = Arc::new(Fake::a_record(Ipv4Addr::LOCALHOST));
    let engine = EngineBuilder::new(&Config::default(), Up(Arc::clone(&fake))).build();
    let r = engine
        .handle(ctx(), query("www.example.", RecordType::A))
        .await;
    assert_eq!(ede_codes(&r), [ede::NO_REACHABLE_AUTHORITY]);
    let mut plain = query("www.example.", RecordType::A);
    plain.edns = None;
    let r = engine.handle(ctx(), plain).await;
    assert_eq!(r.header.rcode, Rcode::ServFail);
    assert!(r.edns.is_none(), "no OPT for a client that sent none");
    engine.set_groups(Some(groups()));
    assert!(engine.groups().is_some());
    let r = engine
        .handle(ctx(), query("www.example.", RecordType::A))
        .await;
    assert_eq!(r.header.rcode, Rcode::NoError);
}

#[tokio::test]
async fn mismatching_upstream_answer_not_cached() {
    let h = harness(Fake::answering(|q| {
        let mut r = Message::response_to(q);
        r.questions[0].name = name("evil.example.");
        r.answers
            .push(rec("evil.example.", RData::A(Ipv4Addr::new(6, 6, 6, 6))));
        Ok(r)
    }));
    let r = h
        .engine
        .handle(ctx(), query("www.example.", RecordType::A))
        .await;
    assert_eq!(r.header.rcode, Rcode::ServFail);
    assert_eq!(ede_codes(&r), [ede::NETWORK_ERROR]);
    assert_eq!(r.answers.len(), 0);
    assert_eq!(h.engine.cache().stats().inserts, 0);
}

#[tokio::test]
async fn upstream_answer_scrubbed_and_negative_cached() {
    let h = harness(Fake::answering(|q| {
        let mut r = Message::response_to(q);
        r.header.aa = true;
        r.header.ad = true;
        r.header.rcode = Rcode::NxDomain;
        r.answers
            .push(rec("bank.example.", RData::A(Ipv4Addr::new(6, 6, 6, 6))));
        r.authority.push(rec(
            "example.",
            RData::Soa(Soa {
                mname: name("ns.example."),
                rname: name("h.example."),
                serial: 1,
                refresh: 1,
                retry: 1,
                expire: 1,
                minimum: 60,
            }),
        ));
        r.additional
            .push(rec("ns.example.", RData::A(Ipv4Addr::new(6, 6, 6, 6))));
        r.edns = Some(Edns {
            options: vec![EdnsOption::Padding(8)],
            ..Edns::default()
        });
        Ok(r)
    }));
    let r = h
        .engine
        .handle(ctx(), query("nope.example.", RecordType::A))
        .await;
    assert_eq!(r.header.rcode, Rcode::NxDomain);
    assert!(!r.header.aa && !r.header.ad);
    assert_eq!(r.answers.len() + r.additional.len(), 0);
    assert_eq!(r.authority.len(), 1);
    assert_eq!(r.edns.unwrap().options.len(), 0);
    h.engine
        .handle(ctx(), query("nope.example.", RecordType::A))
        .await;
    assert_eq!(h.fake.calls(), 1);
}

#[tokio::test]
async fn response_ip_blocked() {
    let policy = ResponseIpPolicy::new(["198.51.100.0/24".parse().unwrap()]);
    let h = harness_with(
        Fake::a_record(Ipv4Addr::new(198, 51, 100, 9)),
        &Config::default(),
        |b| b.response_ip_policy(policy),
    );
    let r = h
        .engine
        .handle(ctx(), query("rebind.example.", RecordType::A))
        .await;
    assert_eq!(r.answers[0].data, RData::A(Ipv4Addr::UNSPECIFIED));
    assert_eq!(ede_codes(&r), [ede::BLOCKED]);
    let ev = h.events.take();
    assert_eq!(
        ev[0].source,
        AnswerSource::Blocked {
            list: RESPONSE_IP_LIST.to_owned()
        }
    );
    // Applied on cache hits too, and policy changes apply immediately.
    h.engine.set_response_ip_policy(ResponseIpPolicy::default());
    let r = h
        .engine
        .handle(ctx(), query("rebind.example.", RecordType::A))
        .await;
    assert_eq!(r.answers[0].data, RData::A(Ipv4Addr::new(198, 51, 100, 9)));
    assert_eq!(h.fake.calls(), 1);
}

#[tokio::test]
async fn acl_refused_logged() {
    let acl = Acl::new(
        AclAction::Allow,
        [(
            AclMatcher::Cidr("192.0.2.0/24".parse().unwrap()),
            AclAction::Refuse,
        )],
    );
    let h = harness_with(
        Fake::a_record(Ipv4Addr::LOCALHOST),
        &Config::default(),
        |b| b.acl(acl),
    );
    let r = h
        .engine
        .handle(ctx(), query("nas.home.test.", RecordType::A))
        .await;
    assert_eq!(r.header.rcode, Rcode::Refused);
    assert_eq!(r.answers.len(), 0);
    let ev = h.events.take();
    assert_eq!(ev.len(), 1);
    assert_eq!(
        (ev[0].rcode, &ev[0].source),
        (Rcode::Refused, &AnswerSource::Refused)
    );

    // Drop: no reply from `process`, REFUSED through `Handler`, still one event.
    h.engine.set_acl(Acl::new(AclAction::Drop, []));
    assert!(
        h.engine
            .process(&ctx(), &query("a.example.", RecordType::A))
            .await
            .is_none()
    );
    let r = h
        .engine
        .handle(ctx(), query("a.example.", RecordType::A))
        .await;
    assert_eq!(r.header.rcode, Rcode::Refused);
    assert_eq!(h.events.take().len(), 2);
}

#[tokio::test]
async fn rate_limited_udp_dropped_tcp_refused() {
    let h = harness_with(
        Fake::a_record(Ipv4Addr::LOCALHOST),
        &Config::default(),
        |b| b.rate_limit(1),
    );
    let q = query("nas.home.test.", RecordType::A);
    // Burst of 2 * qps.
    for _ in 0..2 {
        assert!(h.engine.process(&ctx(), &q).await.is_some());
    }
    assert!(h.engine.process(&ctx(), &q).await.is_none());
    let tcp = RequestContext {
        transport: Transport::Tcp,
        ..ctx()
    };
    let r = h.engine.process(&tcp, &q).await.unwrap();
    assert_eq!(r.header.rcode, Rcode::Refused);
    h.engine.set_rate_limit(0);
    assert!(h.engine.process(&ctx(), &q).await.is_some());
}

#[tokio::test]
async fn rd_clear_for_non_local_refused_and_opcodes() {
    let h = harness(Fake::a_record(Ipv4Addr::LOCALHOST));
    let mut q = query("www.example.", RecordType::A);
    q.header.rd = false;
    assert_eq!(h.engine.handle(ctx(), q).await.header.rcode, Rcode::Refused);
    let mut local = query("nas.home.test.", RecordType::A);
    local.header.rd = false;
    assert_eq!(
        h.engine.handle(ctx(), local).await.header.rcode,
        Rcode::NoError
    );
    let mut notify = query("home.test.", RecordType::Soa);
    notify.header.opcode = Opcode::Notify;
    assert_eq!(
        h.engine.handle(ctx(), notify).await.header.rcode,
        Rcode::NotImp
    );
    let mut v1 = query("www.example.", RecordType::A);
    v1.edns.as_mut().unwrap().version = 1;
    assert_eq!(
        h.engine.handle(ctx(), v1).await.header.rcode,
        Rcode::BadVers
    );
    let mut empty = query("www.example.", RecordType::A);
    empty.questions.clear();
    assert_eq!(
        h.engine.handle(ctx(), empty).await.header.rcode,
        Rcode::FormErr
    );
    assert_eq!(h.fake.calls(), 0);
}

#[tokio::test]
async fn one_event_per_query() {
    let h = harness(Fake::a_record(Ipv4Addr::new(192, 0, 2, 7)));
    let principal = Principal::Token {
        token: TokenId(42),
        user: UserId(1),
    };
    let with_principal = RequestContext {
        principal: Some(principal),
        transport: Transport::Doh,
        ..ctx()
    };
    h.engine
        .handle(with_principal, query("nas.home.test.", RecordType::A))
        .await;
    h.engine
        .handle(ctx(), query("www.example.", RecordType::A))
        .await;
    h.engine
        .handle(ctx(), query("www.example.", RecordType::A))
        .await;
    let ev = h.events.take();
    assert_eq!(ev.len(), 3);
    assert_eq!(ev[0].source, AnswerSource::Authoritative);
    assert_eq!(ev[0].principal.as_deref(), Some("token:42"));
    assert_eq!(ev[0].transport, Transport::Doh);
    assert_eq!(
        ev[0].client,
        "192.0.2.200".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(ev[0].qname, name("nas.home.test."));
    assert!(
        ev.iter()
            .all(|e| e.dnssec == DnssecStatus::Unchecked && e.ts_unix_ms > 0)
    );
    assert_eq!(ev[1].qtype, RecordType::A);
    assert!(matches!(ev[1].source, AnswerSource::Upstream(_)));
    assert_eq!(ev[2].source, AnswerSource::Cache);
}

/// A UDP upstream on port 0 answering every query with one A record (or staying silent).
async fn udp_upstream(silent: bool) -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            if silent {
                continue;
            }
            let q = Message::decode(&buf[..n]).unwrap();
            let mut r = Message::response_to(&q);
            r.header.ra = true;
            r.answers.push(rec(
                &q.questions[0].name.to_string(),
                RData::A(Ipv4Addr::new(192, 0, 2, 99)),
            ));
            socket
                .send_to(&r.encode(4096).unwrap(), from)
                .await
                .unwrap();
        }
    });
    addr
}

async fn assembled(upstream: SocketAddr, timeout_ms: u64) -> (TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let zones_dir = dir.path().join("zones");
    std::fs::create_dir_all(&zones_dir).unwrap();
    std::fs::write(zones_dir.join("home.test.json"), ZONE).unwrap();
    let toml = format!(
        "[zones]\ndir = {:?}\n[resolver]\nupstreams = [\"{upstream}\"]\ntimeout_ms = {timeout_ms}\nattempts = 2\n",
        zones_dir.display().to_string()
    );
    let config = Config::from_toml(&toml).unwrap();
    let store = Store::open(&dir.path().join("dnsy.db")).unwrap();
    dnsy_filter::SourceStore::new(store.clone())
        .add_custom_rule(dnsy_filter::RuleKind::Block, "ads.example")
        .await
        .unwrap();
    let mut builder = EngineBuilder::from_config(&config, &store).await.unwrap();
    assert!(builder.take_querylog_task().is_some());
    (dir, builder.build())
}

#[tokio::test]
async fn from_config_assembles_pipeline() {
    let upstream = udp_upstream(false).await;
    let (_dir, engine) = assembled(upstream, 2000).await;
    let local = engine
        .handle(ctx(), query("nas.home.test.", RecordType::A))
        .await;
    assert!(local.header.aa);
    let r = engine
        .handle(ctx(), query("www.example.", RecordType::A))
        .await;
    assert_eq!(r.answers[0].data, RData::A(Ipv4Addr::new(192, 0, 2, 99)));
    assert!(engine.zone_store().is_some());
    assert!(engine.list_manager().is_some());
    let blocked = engine
        .handle(ctx(), query("ads.example.", RecordType::A))
        .await;
    assert_eq!(ede_codes(&blocked), [ede::FILTERED]);
    let health = engine.groups().unwrap().health("default").unwrap();
    assert_eq!(health[0].upstream.port, upstream.port());
}

#[tokio::test]
async fn from_config_silent_upstream_servfails_within_deadline() {
    let upstream = udp_upstream(true).await;
    let (_dir, engine) = assembled(upstream, 100).await;
    let started = Instant::now();
    let r = engine
        .handle(ctx(), query("www.example.", RecordType::A))
        .await;
    assert_eq!(r.header.rcode, Rcode::ServFail);
    assert_eq!(ede_codes(&r), [ede::NO_REACHABLE_AUTHORITY]);
    assert!(started.elapsed() < Duration::from_millis(1000));
}
