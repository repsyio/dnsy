//! Pipeline hardening: admission before error replies (SEC-09), minimal ANY and refused
//! zone transfers (SEC-14), coalesced cache misses (SEC-02) and the TTL clamps on the first
//! answer of a miss.

use std::sync::atomic::Ordering;
use std::time::Duration;

use super::stale::{Rig, config};
use super::*;
use crate::{Admission, MAX_MISS_WAITERS};

const AXFR: RecordType = RecordType::Unknown(252);
const IXFR: RecordType = RecordType::Unknown(251);
const HINFO: u16 = 13;

/// Malformed-looking requests the pipeline answers with an error rcode when admitted.
fn error_queries() -> Vec<Message> {
    let mut empty = query("www.example.", RecordType::A);
    empty.questions.clear();
    let mut two = query("www.example.", RecordType::A);
    two.questions.push(two.questions[0].clone());
    let mut notify = query("home.test.", RecordType::Soa);
    notify.header.opcode = Opcode::Notify;
    let mut update = query("home.test.", RecordType::Soa);
    update.header.opcode = Opcode::Update;
    let mut v1 = query("www.example.", RecordType::A);
    v1.edns.as_mut().unwrap().version = 1;
    vec![empty, two, notify, update, v1]
}

#[tokio::test]
async fn acl_drop_suppresses_formerr_and_notimp() {
    let h = harness_with(
        Fake::a_record(Ipv4Addr::LOCALHOST),
        &Config::default(),
        |b| b.acl(Acl::new(AclAction::Drop, [])),
    );
    for q in error_queries() {
        assert!(
            h.engine.process(&ctx(), &q).await.is_none(),
            "a dropped client gets no reply to {:?} / {:?}",
            q.header.opcode,
            q.questions.len()
        );
    }
    let events = h.events.take();
    assert_eq!(events.len(), error_queries().len(), "one event per request");
    assert!(events.iter().all(|e| e.source == AnswerSource::Refused));
    assert_eq!(h.fake.calls(), 0);
}

#[tokio::test]
async fn acl_refuse_answers_refused_instead_of_error_rcodes() {
    let h = harness_with(
        Fake::a_record(Ipv4Addr::LOCALHOST),
        &Config::default(),
        |b| b.acl(Acl::new(AclAction::Refuse, [])),
    );
    for q in error_queries() {
        let r = h.engine.process(&ctx(), &q).await.unwrap();
        assert_eq!(r.header.rcode, Rcode::Refused);
    }
}

#[tokio::test]
async fn error_replies_consume_rate_limit() {
    let h = harness_with(
        Fake::a_record(Ipv4Addr::LOCALHOST),
        &Config::default(),
        |b| b.rate_limit(1),
    );
    let mut notify = query("home.test.", RecordType::Soa);
    notify.header.opcode = Opcode::Notify;
    // The burst is 2 * qps: both NOTIFYs are answered and use it up.
    for _ in 0..2 {
        let r = h.engine.process(&ctx(), &notify).await.unwrap();
        assert_eq!(r.header.rcode, Rcode::NotImp);
    }
    assert!(h.engine.process(&ctx(), &notify).await.is_none());
    assert!(
        h.engine
            .process(&ctx(), &query("nas.home.test.", RecordType::A))
            .await
            .is_none(),
        "error replies took the tokens"
    );
}

#[tokio::test]
async fn admit_follows_acl_drop_and_rate_limit() {
    let h = harness_with(
        Fake::a_record(Ipv4Addr::LOCALHOST),
        &Config::default(),
        |b| b.rate_limit(1),
    );
    let client = ctx().client;
    assert_eq!(h.engine.admit(client, Transport::Udp), Admission::Answer);
    assert_eq!(h.engine.admit(client, Transport::Udp), Admission::Answer);
    assert_eq!(
        h.engine.admit(client, Transport::Udp),
        Admission::Drop,
        "the listener-level FORMERR consumes the same tokens"
    );
    // Over the limit on a stream transport the answer is REFUSED, so the FORMERR may go out.
    assert_eq!(h.engine.admit(client, Transport::Tcp), Admission::Answer);
    h.engine.set_rate_limit(0);
    h.engine.set_acl(Acl::new(AclAction::Drop, []));
    assert_eq!(h.engine.admit(client, Transport::Udp), Admission::Drop);
    h.engine.set_acl(Acl::new(AclAction::Refuse, []));
    assert_eq!(h.engine.admit(client, Transport::Udp), Admission::Answer);
}

#[tokio::test]
async fn any_on_local_zone_answers_minimal_hinfo() {
    let h = harness(Fake::a_record(Ipv4Addr::LOCALHOST));
    for qname in ["nas.home.test.", "home.test."] {
        let r = h.engine.handle(ctx(), query(qname, RecordType::Any)).await;
        assert_eq!(r.header.rcode, Rcode::NoError);
        assert!(r.header.aa);
        assert_eq!(r.answers.len(), 1, "{qname}: {:?}", r.answers);
        let hinfo = &r.answers[0];
        assert_eq!(hinfo.name, name(qname));
        assert_eq!(hinfo.ttl, 3789);
        let RData::Opaque { rtype, data } = &hinfo.data else {
            panic!("not HINFO: {hinfo:?}");
        };
        assert_eq!(*rtype, HINFO);
        // CPU "RFC8482", OS "" (RFC 8482 4.2).
        assert_eq!(data.as_slice(), b"\x07RFC8482\x00");
        assert!(r.authority.is_empty() && r.additional.is_empty());
    }
    // A name that does not exist is still NXDOMAIN.
    let r = h
        .engine
        .handle(ctx(), query("ghost.home.test.", RecordType::Any))
        .await;
    assert_eq!(r.header.rcode, Rcode::NxDomain);
    assert_eq!(h.fake.calls(), 0);
}

#[tokio::test]
async fn any_for_forwarded_name_refused_without_upstream() {
    let h = harness(Fake::a_record(Ipv4Addr::LOCALHOST));
    let r = h
        .engine
        .handle(ctx(), query("www.example.", RecordType::Any))
        .await;
    assert_eq!(r.header.rcode, Rcode::Refused);
    assert_eq!(r.answers, []);
    assert_eq!(h.fake.calls(), 0);
    assert_eq!(h.events.take()[0].source, AnswerSource::Refused);
}

#[tokio::test]
async fn axfr_refused_without_upstream_call() {
    let h = harness(Fake::a_record(Ipv4Addr::LOCALHOST));
    for qtype in [AXFR, IXFR] {
        for qname in ["home.test.", "www.example."] {
            let r = h.engine.handle(ctx(), query(qname, qtype)).await;
            assert_eq!(r.header.rcode, Rcode::Refused, "{qname} {qtype:?}");
            assert!(r.answers.is_empty() && r.authority.is_empty());
            let tcp = RequestContext {
                transport: Transport::Tcp,
                ..ctx()
            };
            let r = h.engine.handle(tcp, query(qname, qtype)).await;
            assert_eq!(r.header.rcode, Rcode::Refused, "TCP {qname} {qtype:?}");
        }
    }
    assert_eq!(h.fake.calls(), 0);
    assert!(
        h.events
            .take()
            .iter()
            .all(|e| e.source == AnswerSource::Refused)
    );
}

/// `n` concurrent asks of `qname` (A) with the DO and CD bits given.
async fn ask_many(rig: &Rig, n: usize, qname: &str, do_bit: bool, cd: bool) -> Vec<Message> {
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..n {
        let engine = Arc::clone(&rig.engine);
        let mut q = query(qname, RecordType::A);
        q.edns.as_mut().unwrap().dnssec_ok = do_bit;
        q.header.cd = cd;
        tasks.spawn(async move { engine.handle(ctx(), q).await });
    }
    tasks.join_all().await
}

fn no_validation() -> Config {
    let mut c = config();
    c.dnssec.validation = dnsy_config::Validation::Off;
    // Floods below come from one client: no rate limit in the way.
    c.limits.per_client_qps = 0;
    c
}

#[tokio::test]
async fn concurrent_identical_misses_share_one_upstream_exchange() {
    let rig = Rig::new(&no_validation(), Duration::from_millis(200));
    let answers = ask_many(&rig, 32, "www.example.", false, false).await;
    assert_eq!(rig.calls(), 1, "32 concurrent misses, one exchange");
    for r in &answers {
        assert_eq!(r.header.rcode, Rcode::NoError);
        assert_eq!(r.answers[0].data, RData::A(Ipv4Addr::new(192, 0, 2, 7)));
    }
}

#[tokio::test]
async fn coalescing_is_per_key() {
    let rig = Rig::new(&no_validation(), Duration::from_millis(200));
    let (plain, with_do, with_cd, upper, other) = tokio::join!(
        ask_many(&rig, 8, "www.example.", false, false),
        ask_many(&rig, 8, "www.example.", true, false),
        ask_many(&rig, 8, "www.example.", false, true),
        ask_many(&rig, 8, "WWW.Example.", false, false),
        ask_many(&rig, 8, "other.example.", false, false),
    );
    // DO, CD and the name each make a different key; the name's case does not.
    assert_eq!(rig.calls(), 4);
    for r in plain
        .iter()
        .chain(&with_do)
        .chain(&with_cd)
        .chain(&upper)
        .chain(&other)
    {
        assert_eq!(r.header.rcode, Rcode::NoError);
    }
    // Each follower is answered with its own id and question casing.
    assert!(
        upper
            .iter()
            .all(|r| r.questions[0].name.to_string() == "WWW.Example.")
    );
}

#[tokio::test]
async fn failed_miss_is_shared_only_while_in_flight() {
    let rig = Rig::new(&no_validation(), Duration::from_millis(200));
    rig.up.up.store(false, Ordering::SeqCst);
    let answers = ask_many(&rig, 8, "www.example.", false, false).await;
    assert!(answers.iter().all(|r| r.header.rcode == Rcode::ServFail));
    let shared = rig.calls();
    assert!(
        shared <= 2,
        "one exchange per attempt, not per client: {shared}"
    );
    // The failure is not remembered: the next miss asks again and succeeds.
    rig.up.up.store(true, Ordering::SeqCst);
    let r = rig.ask("www.example.").await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert!(rig.calls() > shared);
}

#[tokio::test]
async fn cancelled_leader_does_not_hang_followers() {
    let rig = Rig::new(&no_validation(), Duration::from_millis(300));
    let engine = Arc::clone(&rig.engine);
    let leader = tokio::spawn(async move {
        engine
            .handle(ctx(), query("www.example.", RecordType::A))
            .await
    });
    while rig.calls() == 0 {
        tokio::task::yield_now().await;
    }
    let engine = Arc::clone(&rig.engine);
    let follower = tokio::spawn(async move {
        engine
            .handle(ctx(), query("www.example.", RecordType::A))
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    leader.abort();
    let r = tokio::time::timeout(Duration::from_secs(5), follower)
        .await
        .expect("the follower is not left waiting")
        .unwrap();
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert_eq!(rig.calls(), 2, "the follower took over the exchange");
}

#[tokio::test]
async fn waiters_per_key_are_bounded() {
    let rig = Rig::new(&no_validation(), Duration::from_millis(500));
    let started = Instant::now();
    let answers = ask_many(&rig, MAX_MISS_WAITERS + 41, "www.example.", false, false).await;
    assert_eq!(rig.calls(), 1);
    let served = answers
        .iter()
        .filter(|r| r.header.rcode == Rcode::NoError)
        .count();
    assert_eq!(served, MAX_MISS_WAITERS + 1, "the leader and the waiters");
    let busy: Vec<_> = answers
        .iter()
        .filter(|r| r.header.rcode == Rcode::ServFail)
        .collect();
    assert_eq!(busy.len(), 40);
    assert!(
        busy.iter()
            .all(|r| ede_codes(r) == vec![ede::NO_REACHABLE_AUTHORITY])
    );
    assert!(started.elapsed() >= Duration::from_millis(500));
}

#[tokio::test]
async fn first_miss_answer_is_ttl_clamped() {
    let mut c = no_validation();
    c.cache.min_ttl = 600;
    let rig = Rig::new(&c, Duration::ZERO);
    let first = rig.ask("www.example.").await;
    assert_eq!(
        first.answers[0].ttl, 600,
        "upstream TTL 300 raised to min_ttl"
    );

    let mut c = no_validation();
    c.cache.max_ttl = 60;
    let rig = Rig::new(&c, Duration::ZERO);
    let first = rig.ask("www.example.").await;
    assert_eq!(
        first.answers[0].ttl, 60,
        "upstream TTL 300 lowered to max_ttl"
    );
    let cached = rig.ask("www.example.").await;
    assert_eq!(cached.answers[0].ttl, first.answers[0].ttl);
    assert_eq!(rig.calls(), 1);
}

#[tokio::test]
async fn uncacheable_miss_is_served_as_received() {
    let mut c = no_validation();
    c.cache.enabled = false;
    c.cache.min_ttl = 600;
    let rig = Rig::new(&c, Duration::ZERO);
    assert_eq!(rig.ask("www.example.").await.answers[0].ttl, 300);
}
