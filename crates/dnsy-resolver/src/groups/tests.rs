use std::collections::HashMap;
use std::sync::atomic::AtomicU64;

use dnsy_core::{Clock, ManualClock, SystemClock};
use dnsy_store::Store;

use std::net::SocketAddr;

use super::health::backoff;
use super::*;

/// splitmix64: deterministic and well distributed.
struct SeededRng(AtomicU64);

impl Rng for SeededRng {
    fn next_u64(&self) -> u64 {
        let mut z = self
            .0
            .fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed)
            .wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Fake network: per-upstream latency (advances the manual clock) and up/down switch; records
/// how often each upstream was asked.
struct Fake {
    clock: Arc<ManualClock>,
    latency: HashMap<String, Duration>,
    down: Mutex<HashSet<String>>,
    hits: Mutex<HashMap<String, u32>>,
}

impl Exchange for Fake {
    async fn exchange(
        &self,
        upstream: &Upstream,
        query: &Message,
    ) -> Result<Message, UpstreamError> {
        let key = upstream.to_string();
        *self.hits.lock().unwrap().entry(key.clone()).or_default() += 1;
        self.clock.advance_by(
            self.latency
                .get(&key)
                .copied()
                .unwrap_or(Duration::from_millis(1)),
        );
        tokio::task::yield_now().await;
        if self.down.lock().unwrap().contains(&key) {
            return Err(UpstreamError::Timeout);
        }
        Ok(Message::response_to(query))
    }
}

impl Fake {
    fn hits(&self, u: &str) -> u32 {
        self.hits.lock().unwrap().get(u).copied().unwrap_or(0)
    }
    fn set_down(&self, u: &str, down: bool) {
        let mut d = self.down.lock().unwrap();
        if down {
            d.insert(u.to_owned());
        } else {
            d.remove(u);
        }
    }
}

fn up(host: &str) -> Upstream {
    format!("udp://{host}").parse().unwrap()
}

fn u(host: &str) -> String {
    up(host).to_string()
}

fn member(host: &str, weight: u32) -> GroupMember {
    GroupMember {
        upstream: up(host),
        weight,
    }
}

fn spec(name: &str, strategy: Strategy, hosts: &[&str]) -> GroupSpec {
    GroupSpec {
        name: name.to_owned(),
        strategy,
        default: false,
        domains: vec![],
        members: hosts.iter().map(|h| member(h, 1)).collect(),
    }
}

fn setup(specs: Vec<GroupSpec>, latency: &[(&str, u64)]) -> (GroupSet, Fake, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(0));
    let set = GroupSet::new(
        specs,
        clock.clone(),
        Arc::new(SeededRng(AtomicU64::new(42))),
    )
    .unwrap();
    let fake = Fake {
        clock: clock.clone(),
        latency: latency
            .iter()
            .map(|(h, ms)| (u(h), Duration::from_millis(*ms)))
            .collect(),
        down: Mutex::default(),
        hits: Mutex::default(),
    };
    (set, fake, clock)
}

fn default_spec(strategy: Strategy, hosts: &[&str]) -> GroupSpec {
    GroupSpec {
        default: true,
        ..spec("default", strategy, hosts)
    }
}

fn query(name: &str) -> Message {
    let mut m = probe_query();
    m.questions[0] = Question {
        name: Name::from_ascii(name).unwrap(),
        qtype: RecordType::A,
        qclass: Class::In,
    };
    m
}

#[tokio::test]
async fn round_robin_distribution() {
    let (set, fake, _) = setup(
        vec![default_spec(
            Strategy::RoundRobin,
            &["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        )],
        &[],
    );
    for _ in 0..30 {
        set.resolve(&fake, &query("a.example")).await.unwrap();
    }
    for h in ["10.0.0.1", "10.0.0.2", "10.0.0.3"] {
        assert_eq!(fake.hits(&u(h)), 10, "{h}");
    }
}

#[tokio::test]
async fn weighted_distribution_within_tolerance() {
    let mut s = default_spec(Strategy::Weighted, &[]);
    s.members = vec![member("10.0.0.1", 1), member("10.0.0.2", 3)];
    let (set, fake, _) = setup(vec![s], &[]);
    for _ in 0..4000 {
        set.resolve(&fake, &query("a.example")).await.unwrap();
    }
    let heavy = f64::from(fake.hits(&u("10.0.0.2")));
    let ratio = heavy / 4000.0;
    assert!((ratio - 0.75).abs() < 0.03, "ratio {ratio}");
}

#[tokio::test]
async fn lowest_latency_prefers_fast() {
    let (set, fake, _) = setup(
        vec![default_spec(
            Strategy::LowestLatency,
            &["10.0.0.1", "10.0.0.2"],
        )],
        &[("10.0.0.1", 80), ("10.0.0.2", 5)],
    );
    for _ in 0..20 {
        set.resolve(&fake, &query("a.example")).await.unwrap();
    }
    // Each is sampled once while unmeasured; afterwards only the fast one is used.
    assert_eq!(fake.hits(&u("10.0.0.1")), 1);
    assert_eq!(fake.hits(&u("10.0.0.2")), 19);
    let h = set.health("default").unwrap();
    assert_eq!(h[0].latency_ewma, Some(Duration::from_millis(80)));
    assert_eq!(h[1].latency_ewma, Some(Duration::from_millis(5)));
}

#[tokio::test]
async fn ewma_weights_recent_samples() {
    let mut hl = Health::default();
    hl.record_success(Duration::from_millis(100));
    hl.record_success(Duration::from_millis(0));
    assert_eq!(hl.ewma(), Some(Duration::from_millis(70)));
}

#[tokio::test]
async fn failover_order() {
    let (set, fake, _) = setup(
        vec![default_spec(
            Strategy::Failover,
            &["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        )],
        &[],
    );
    for _ in 0..5 {
        set.resolve(&fake, &query("a.example")).await.unwrap();
    }
    assert_eq!(fake.hits(&u("10.0.0.1")), 5);
    assert_eq!(fake.hits(&u("10.0.0.2")), 0);
    fake.set_down(&u("10.0.0.1"), true);
    set.resolve(&fake, &query("a.example")).await.unwrap();
    assert_eq!(fake.hits(&u("10.0.0.1")), 6);
    assert_eq!(fake.hits(&u("10.0.0.2")), 1);
    assert_eq!(fake.hits(&u("10.0.0.3")), 0);
}

#[tokio::test]
async fn ejection_and_recovery() {
    let (set, fake, clock) = setup(
        vec![default_spec(Strategy::Failover, &["10.0.0.1", "10.0.0.2"])],
        &[],
    );
    let a = u("10.0.0.1");
    fake.set_down(&a, true);
    for _ in 0..3 {
        set.resolve(&fake, &query("a.example")).await.unwrap();
    }
    assert_eq!(fake.hits(&a), 3);
    assert!(!set.health("default").unwrap()[0].available);
    // Ejected: no longer tried.
    set.resolve(&fake, &query("a.example")).await.unwrap();
    assert_eq!(fake.hits(&a), 3);

    // Backoff not over: no probe.
    clock.advance_by(Duration::from_secs(3));
    set.run_probes(&fake).await;
    assert_eq!(fake.hits(&a), 3);

    // Backoff over but still down: probe fails, backoff doubles to 10 s.
    clock.advance_by(Duration::from_secs(3));
    set.run_probes(&fake).await;
    assert_eq!(fake.hits(&a), 4);
    clock.advance_by(Duration::from_secs(9));
    set.run_probes(&fake).await;
    assert_eq!(fake.hits(&a), 4);

    // Back up: the next probe re-admits it.
    fake.set_down(&a, false);
    clock.advance_by(Duration::from_secs(2));
    set.run_probes(&fake).await;
    let h = &set.health("default").unwrap()[0];
    assert!(h.available);
    assert_eq!(h.consecutive_failures, 0);
    set.resolve(&fake, &query("a.example")).await.unwrap();
    assert_eq!(fake.hits(&a), 6);
}

#[test]
fn backoff_doubles_from_5s_to_5min() {
    let secs: Vec<u64> = (1..=9).map(|n| backoff(n).as_secs()).collect();
    assert_eq!(secs, [5, 10, 20, 40, 80, 160, 300, 300, 300]);
    assert_eq!(backoff(u32::MAX).as_secs(), 300);
}

#[test]
fn two_failures_do_not_eject_and_success_resets() {
    let mut hl = Health::default();
    hl.record_failure(Duration::ZERO);
    hl.record_failure(Duration::ZERO);
    assert!(hl.is_available());
    hl.record_success(Duration::from_millis(1));
    hl.record_failure(Duration::ZERO);
    hl.record_failure(Duration::ZERO);
    assert!(hl.is_available());
}

#[test]
fn straggler_failures_do_not_extend_ejection() {
    let mut hl = Health::default();
    for _ in 0..3 {
        hl.record_failure(Duration::ZERO);
    }
    hl.record_failure(Duration::from_secs(1));
    assert!(!hl.probe_due(Duration::from_secs(4)));
    assert!(hl.probe_due(Duration::from_secs(5)));
}

#[tokio::test]
async fn all_ejected_is_an_error_and_all_failing_reports_last_error() {
    let (set, fake, _) = setup(vec![default_spec(Strategy::Failover, &["10.0.0.1"])], &[]);
    fake.set_down(&u("10.0.0.1"), true);
    for _ in 0..3 {
        assert!(matches!(
            set.resolve(&fake, &query("a.example")).await,
            Err(GroupError::AllFailed(UpstreamError::Timeout))
        ));
    }
    assert!(matches!(
        set.resolve(&fake, &query("a.example")).await,
        Err(GroupError::NoAvailableUpstream(g)) if g == "default"
    ));
}

#[tokio::test]
async fn domain_routing() {
    let mut corp = spec("corp", Strategy::Failover, &["10.9.0.1"]);
    corp.domains = vec!["*.corp.example".to_owned()];
    let mut deep = spec("deep", Strategy::Failover, &["10.8.0.1"]);
    deep.domains = vec!["db.corp.example".to_owned()];
    let (set, fake, _) = setup(
        vec![default_spec(Strategy::Failover, &["10.0.0.1"]), corp, deep],
        &[],
    );
    let group = |n: &str| set.group_for(&Name::from_ascii(n).unwrap()).to_owned();
    assert_eq!(group("www.corp.example"), "corp");
    assert_eq!(group("WWW.Corp.Example"), "corp");
    assert_eq!(group("corp.example"), "corp");
    assert_eq!(group("x.db.corp.example"), "deep");
    assert_eq!(group("example"), "default");
    assert_eq!(group("notcorp.example"), "default");
    set.resolve(&fake, &query("www.corp.example"))
        .await
        .unwrap();
    set.resolve(&fake, &query("www.other.test")).await.unwrap();
    assert_eq!(fake.hits(&u("10.9.0.1")), 1);
    assert_eq!(fake.hits(&u("10.0.0.1")), 1);
}

#[tokio::test]
async fn query_without_question_is_rejected() {
    let (set, fake, _) = setup(vec![default_spec(Strategy::Failover, &["10.0.0.1"])], &[]);
    let mut q = query("a.example");
    q.questions.clear();
    assert!(matches!(
        set.resolve(&fake, &q).await,
        Err(GroupError::NoQuestion)
    ));
}

#[test]
fn invalid_configuration_is_rejected() {
    let build = |specs| {
        GroupSet::new(specs, Arc::new(SystemClock), Arc::new(ThreadRng))
            .err()
            .map(|e| e.to_string())
    };
    let d = default_spec(Strategy::Failover, &["10.0.0.1"]);
    assert!(build(vec![d.clone()]).is_none());
    assert!(build(vec![]).unwrap().contains("no default"));
    assert!(
        build(vec![
            d.clone(),
            GroupSpec {
                name: "b".into(),
                ..d.clone()
            }
        ])
        .unwrap()
        .contains("more than one default")
    );
    assert!(
        build(vec![d.clone(), d.clone()])
            .unwrap()
            .contains("duplicate")
    );
    let mut empty = d.clone();
    empty.members.clear();
    assert!(build(vec![empty]).unwrap().contains("members"));
    let mut zero = d.clone();
    zero.members[0].weight = 0;
    assert!(build(vec![zero]).unwrap().contains("weight"));
    let mut bad = d.clone();
    bad.domains = vec!["a..b".into()];
    assert!(build(vec![bad]).unwrap().contains("pattern"));
    let mut a = spec("a", Strategy::Failover, &["10.0.0.2"]);
    a.domains = vec!["x.test".into()];
    let mut b = spec("b", Strategy::Failover, &["10.0.0.3"]);
    b.domains = vec!["*.x.test".into()];
    assert!(build(vec![d, a, b]).unwrap().contains("twice"));
}

#[test]
fn strategy_names_round_trip() {
    for s in [
        Strategy::RoundRobin,
        Strategy::Weighted,
        Strategy::LowestLatency,
        Strategy::Failover,
    ] {
        assert_eq!(Strategy::parse(s.as_str()), Some(s));
    }
    assert_eq!(Strategy::parse("nope"), None);
}

#[test]
fn production_clock_and_rng_work() {
    let c = SystemClock;
    assert!(c.instant() <= c.instant());
    let r = ThreadRng;
    assert_ne!((r.next_u64(), r.next_u64()), (0, 0));
}

fn temp_store() -> (GroupStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("t.db")).unwrap();
    (GroupStore::new(store), dir)
}

#[tokio::test]
async fn store_round_trip_and_replace() {
    let (gs, _d) = temp_store();
    let mut corp = spec("corp", Strategy::Weighted, &["10.9.0.1"]);
    corp.members.push(GroupMember {
        upstream: "tls://1.1.1.1#cloudflare-dns.com".parse().unwrap(),
        weight: 5,
    });
    corp.domains = vec!["corp.example".into(), "*.lan".into()];
    gs.put(&default_spec(Strategy::Failover, &["10.0.0.1"]))
        .await
        .unwrap();
    gs.put(&corp).await.unwrap();
    let list = gs.list().await.unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0], corp);
    assert!(list[1].default);

    corp.members.remove(0);
    corp.default = true;
    gs.put(&corp).await.unwrap();
    let list = gs.list().await.unwrap();
    assert_eq!(list[0].members.len(), 1);
    assert!(list[0].default && !list[1].default);

    assert!(gs.delete("corp").await.unwrap());
    assert!(!gs.delete("corp").await.unwrap());
    assert_eq!(gs.list().await.unwrap().len(), 1);
}

#[tokio::test]
async fn config_seeds_on_first_start_only() {
    let (gs, _d) = temp_store();
    let addrs: Vec<SocketAddr> = vec![
        "1.1.1.1:53".parse().unwrap(),
        "[2606:4700::1111]:53".parse().unwrap(),
    ];
    assert!(!gs.seed_default(&[]).await.unwrap());
    assert!(gs.seed_default(&addrs).await.unwrap());
    let list = gs.list().await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, DEFAULT_GROUP);
    assert!(list[0].default);
    assert_eq!(list[0].members[1].upstream.host, "2606:4700::1111");
    // A later start with different config leaves operator changes alone.
    assert!(
        !gs.seed_default(&["9.9.9.9:53".parse().unwrap()])
            .await
            .unwrap()
    );
    assert_eq!(gs.list().await.unwrap(), list);
    GroupSet::new(list, Arc::new(SystemClock), Arc::new(ThreadRng)).unwrap();
}

#[test]
fn from_specs_builds_a_set_and_rejects_an_invalid_one() {
    let mut s = spec("main", Strategy::Failover, &["192.0.2.1"]);
    s.default = true;
    let set = GroupSet::from_specs(vec![s.clone()]).unwrap();
    assert_eq!(
        set.group_for(&Name::from_ascii("a.example.").unwrap()),
        "main"
    );
    s.default = false;
    assert!(GroupSet::from_specs(vec![s]).is_err());
}
