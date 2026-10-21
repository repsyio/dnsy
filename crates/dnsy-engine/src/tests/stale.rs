//! Serve-stale (RFC 8767) and prefetch through the pipeline, with a hand-driven cache clock.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::*;

/// Upstream that can be switched off, slowed down and made to answer NXDOMAIN; it tracks the
/// peak number of concurrent exchanges.
struct Switch {
    up: AtomicBool,
    nxdomain: AtomicBool,
    delay_ms: AtomicU64,
    calls: AtomicUsize,
    active: AtomicUsize,
    peak: AtomicUsize,
    ip: Mutex<Ipv4Addr>,
}

impl Switch {
    fn new(delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            up: AtomicBool::new(true),
            nxdomain: AtomicBool::new(false),
            delay_ms: AtomicU64::new(u64::try_from(delay.as_millis()).unwrap()),
            calls: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            ip: Mutex::new(Ipv4Addr::new(192, 0, 2, 7)),
        })
    }
}

struct Sw(Arc<Switch>);

impl Exchange for Sw {
    async fn exchange(&self, _: &Upstream, query: &Message) -> Result<Message, UpstreamError> {
        let s = &self.0;
        s.calls.fetch_add(1, Ordering::SeqCst);
        let now = s.active.fetch_add(1, Ordering::SeqCst) + 1;
        s.peak.fetch_max(now, Ordering::SeqCst);
        let delay = s.delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        s.active.fetch_sub(1, Ordering::SeqCst);
        if !s.up.load(Ordering::SeqCst) {
            return Err(UpstreamError::Timeout);
        }
        let mut r = Message::response_to(query);
        let owner = query.questions[0].name.to_string();
        if s.nxdomain.load(Ordering::SeqCst) {
            r.header.rcode = Rcode::NxDomain;
            r.authority.push(Record {
                ttl: 300,
                ..rec(
                    "example.",
                    RData::Soa(Soa {
                        mname: name("ns.example."),
                        rname: name("h.example."),
                        serial: 1,
                        refresh: 1,
                        retry: 1,
                        expire: 1,
                        minimum: 300,
                    }),
                )
            });
        } else {
            r.answers.push(rec(&owner, RData::A(*s.ip.lock().unwrap())));
        }
        Ok(r)
    }
}

struct Rig {
    engine: Arc<Engine<Sw>>,
    up: Arc<Switch>,
    skew: Arc<AtomicUsize>,
}

impl Rig {
    fn new(config: &Config, delay: Duration) -> Self {
        let up = Switch::new(delay);
        let base = Instant::now();
        let skew = Arc::new(AtomicUsize::new(0));
        let clock = Arc::clone(&skew);
        let engine = EngineBuilder::new(config, Sw(Arc::clone(&up)))
            .groups(groups())
            .clock(move || base + Duration::from_secs(clock.load(Ordering::SeqCst) as u64))
            .build();
        Self {
            engine: Arc::new(engine),
            up,
            skew,
        }
    }

    /// Starts the prefetch workers and waits until they are up.
    async fn start_prefetch(&self) -> tokio::task::JoinHandle<()> {
        let engine = Arc::clone(&self.engine);
        let task = tokio::spawn(async move { engine.run_prefetch().await });
        while !self.engine.prefetch_running() {
            tokio::task::yield_now().await;
        }
        task
    }

    fn advance(&self, secs: usize) {
        self.skew.fetch_add(secs, Ordering::SeqCst);
    }

    async fn ask(&self, qname: &str) -> Message {
        self.engine.handle(ctx(), query(qname, RecordType::A)).await
    }

    fn calls(&self) -> usize {
        self.up.calls.load(Ordering::SeqCst)
    }
}

fn config() -> Config {
    let mut c = Config::default();
    c.cache.prefetch.enabled = false;
    c
}

#[tokio::test]
async fn upstream_down_serves_stale_with_ede3() {
    let rig = Rig::new(&config(), Duration::ZERO);
    let first = rig.ask("www.example.").await;
    assert_eq!(first.answers[0].ttl, 300);
    rig.advance(400);
    rig.up.up.store(false, Ordering::SeqCst);
    let r = rig.ask("www.example.").await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert_eq!(r.answers[0].data, first.answers[0].data);
    assert_eq!(r.answers[0].ttl, 30);
    assert_eq!(ede_codes(&r), vec![ede::STALE_ANSWER]);
    assert_eq!(rig.engine.cache().stats().stale_served, 1);
}

#[tokio::test]
async fn stale_answer_is_logged_as_cache_stale() {
    let events = Arc::new(Events::default());
    let up = Switch::new(Duration::ZERO);
    let base = Instant::now();
    let skew = Arc::new(AtomicUsize::new(0));
    let clock = Arc::clone(&skew);
    let engine = EngineBuilder::new(&config(), Sw(Arc::clone(&up)))
        .groups(groups())
        .sink(Arc::clone(&events) as Arc<dyn QueryEventSink>)
        .clock(move || base + Duration::from_secs(clock.load(Ordering::SeqCst) as u64))
        .build();
    engine
        .handle(ctx(), query("a.example.", RecordType::A))
        .await;
    skew.store(400, Ordering::SeqCst);
    up.up.store(false, Ordering::SeqCst);
    engine
        .handle(ctx(), query("a.example.", RecordType::A))
        .await;
    let sources: Vec<_> = events.take().into_iter().map(|e| e.source).collect();
    assert_eq!(sources[1], AnswerSource::CacheStale);
}

#[tokio::test]
async fn stale_nxdomain_ede19() {
    let rig = Rig::new(&config(), Duration::ZERO);
    rig.up.nxdomain.store(true, Ordering::SeqCst);
    assert_eq!(rig.ask("gone.example.").await.header.rcode, Rcode::NxDomain);
    rig.advance(400);
    rig.up.up.store(false, Ordering::SeqCst);
    let r = rig.ask("gone.example.").await;
    assert_eq!(r.header.rcode, Rcode::NxDomain);
    assert_eq!(ede_codes(&r), vec![ede::STALE_NXDOMAIN]);
}

#[tokio::test]
async fn stale_not_served_past_max_stale() {
    let mut c = config();
    c.cache.serve_stale.max_stale = 1000;
    let rig = Rig::new(&c, Duration::ZERO);
    rig.ask("www.example.").await;
    rig.up.up.store(false, Ordering::SeqCst);
    rig.advance(300 + 1001);
    let r = rig.ask("www.example.").await;
    assert_eq!(r.header.rcode, Rcode::ServFail);
    assert_eq!(ede_codes(&r), vec![ede::NO_REACHABLE_AUTHORITY]);
}

#[tokio::test]
async fn stale_disabled_servfails_when_expired() {
    let mut c = config();
    c.cache.serve_stale.enabled = false;
    let rig = Rig::new(&c, Duration::ZERO);
    rig.ask("www.example.").await;
    rig.up.up.store(false, Ordering::SeqCst);
    rig.advance(400);
    assert_eq!(rig.ask("www.example.").await.header.rcode, Rcode::ServFail);
}

#[tokio::test]
async fn refresh_replaces_stale() {
    let rig = Rig::new(&config(), Duration::ZERO);
    rig.ask("www.example.").await;
    rig.advance(400);
    *rig.up.ip.lock().unwrap() = Ipv4Addr::new(192, 0, 2, 99);
    let r = rig.ask("www.example.").await;
    assert_eq!(r.answers[0].data, RData::A(Ipv4Addr::new(192, 0, 2, 99)));
    assert_eq!(ede_codes(&r), Vec::<u16>::new());
    let again = rig.ask("www.example.").await;
    assert_eq!(again.answers[0].data, r.answers[0].data);
    assert_eq!(rig.calls(), 2, "the refreshed entry is a normal hit");
    assert_eq!(rig.engine.cache().stats().stale_served, 0);
}

#[tokio::test]
async fn refresh_coalesced_single_upstream_query() {
    let rig = Rig::new(&config(), Duration::from_millis(150));
    rig.ask("www.example.").await;
    rig.advance(400);
    let (a, b, c) = tokio::join!(
        rig.ask("www.example."),
        rig.ask("www.example."),
        rig.ask("www.example.")
    );
    assert_eq!(rig.calls(), 2, "one fill plus one shared refresh");
    let stale = [&a, &b, &c]
        .iter()
        .filter(|r| ede_codes(r) == vec![ede::STALE_ANSWER])
        .count();
    assert_eq!(stale, 2, "followers answer stale instead of querying");
    assert!(rig.engine.refreshes.is_empty());
}

#[tokio::test]
async fn slow_refresh_answers_stale_after_client_timeout() {
    let mut c = config();
    c.cache.serve_stale.client_timeout_ms = 50;
    let rig = Rig::new(&c, Duration::from_millis(600));
    rig.ask("www.example.").await;
    rig.advance(400);
    let started = Instant::now();
    let r = rig.ask("www.example.").await;
    assert!(started.elapsed() < Duration::from_millis(400));
    assert_eq!(ede_codes(&r), vec![ede::STALE_ANSWER]);
}

fn prefetching() -> Config {
    let mut c = Config::default();
    c.limits.per_client_qps = 0;
    c.cache.prefetch.min_hits = 2;
    c.cache.prefetch.remaining_ttl_pct = 10;
    c
}

#[tokio::test]
async fn prefetch_triggers_for_popular_entry() {
    let rig = Rig::new(&prefetching(), Duration::ZERO);
    drop(rig.start_prefetch().await);
    rig.ask("www.example.").await;
    rig.ask("www.example.").await;
    rig.ask("www.example.").await;
    rig.advance(275);
    let served = rig.ask("www.example.").await;
    assert_eq!(
        served.answers[0].ttl, 25,
        "the client still gets the live entry"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(rig.calls(), 2);
    assert_eq!(rig.engine.cache().stats().prefetches, 1);
    rig.advance(100);
    let after = rig.ask("www.example.").await;
    assert_eq!(
        after.answers[0].ttl, 200,
        "served from the prefetched entry"
    );
    assert_eq!(rig.calls(), 2);
}

#[tokio::test]
async fn prefetch_not_triggered_below_min_hits() {
    let rig = Rig::new(&prefetching(), Duration::ZERO);
    drop(rig.start_prefetch().await);
    rig.ask("www.example.").await;
    rig.advance(275);
    rig.ask("www.example.").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(rig.calls(), 1);
    assert_eq!(rig.engine.cache().stats().prefetches, 0);
}

#[tokio::test]
async fn prefetch_concurrency_bounded() {
    let rig = Rig::new(&prefetching(), Duration::from_millis(120));
    drop(rig.start_prefetch().await);
    let names: Vec<String> = (0..12).map(|i| format!("h{i}.example.")).collect();
    for n in &names {
        for _ in 0..3 {
            rig.ask(n).await;
        }
    }
    rig.advance(280);
    rig.up.peak.store(0, Ordering::SeqCst);
    for n in &names {
        rig.ask(n).await;
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(rig.engine.cache().stats().prefetches, 12);
    let peak = rig.up.peak.load(Ordering::SeqCst);
    assert!((1..=4).contains(&peak), "peak {peak}");
}

#[tokio::test]
async fn prefetch_failure_leaves_entry_and_frees_slot() {
    let rig = Rig::new(&prefetching(), Duration::ZERO);
    drop(rig.start_prefetch().await);
    for _ in 0..3 {
        rig.ask("www.example.").await;
    }
    rig.advance(275);
    rig.up.up.store(false, Ordering::SeqCst);
    rig.ask("www.example.").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(rig.engine.refreshes.is_empty());
    assert_eq!(rig.ask("www.example.").await.answers[0].ttl, 25);
}

#[tokio::test]
async fn no_worker_means_no_enqueue_and_no_leaked_slot() {
    let rig = Rig::new(&prefetching(), Duration::ZERO);
    for _ in 0..3 {
        rig.ask("www.example.").await;
    }
    rig.advance(275);
    rig.ask("www.example.").await;
    assert!(rig.engine.refreshes.is_empty());
    assert_eq!(rig.engine.cache().stats().prefetches, 0);
    // The expired entry is refreshed by the client that finds it stale.
    rig.advance(30);
    let r = rig.ask("www.example.").await;
    assert_eq!(ede_codes(&r), Vec::<u16>::new());
    assert_eq!(rig.calls(), 2);
    // A worker that starts later finds nothing queued.
    let worker = rig.start_prefetch().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    worker.abort();
    assert_eq!(rig.calls(), 2);
}

#[tokio::test]
async fn full_prefetch_queue_does_not_block_client_refresh() {
    let rig = Rig::new(&prefetching(), Duration::ZERO);
    let names: Vec<String> = (0..72).map(|i| format!("h{i}.example.")).collect();
    for n in &names {
        for _ in 0..3 {
            rig.ask(n).await;
        }
    }
    let worker = rig.start_prefetch().await;
    rig.up.delay_ms.store(400, Ordering::SeqCst);
    rig.advance(280);
    for n in &names {
        rig.ask(n).await;
    }
    // Four jobs run, 64 wait, the rest were dropped; the entries now expire.
    rig.advance(30);
    let last = names.last().unwrap();
    let r = rig.ask(last).await;
    assert_eq!(
        ede_codes(&r),
        Vec::<u16>::new(),
        "refreshed, not served stale"
    );
    assert!(r.answers[0].ttl > 30, "a fresh answer, not the stale TTL");
    worker.abort();
}

#[tokio::test]
async fn queued_job_does_not_hold_the_refresh_slot() {
    let rig = Rig::new(&prefetching(), Duration::ZERO);
    for _ in 0..3 {
        rig.ask("www.example.").await;
    }
    rig.advance(275);
    // A worker counts as running but never takes the job (all four busy elsewhere is the
    // real-world case; here the receiver lock is held).
    let held = rig.engine.prefetch_rx.lock().await;
    let _running = rig.start_prefetch().await;
    rig.ask("www.example.").await;
    assert!(rig.engine.refreshes.is_empty(), "queued job holds no slot");
    rig.advance(30);
    let r = rig.ask("www.example.").await;
    assert_eq!(ede_codes(&r), Vec::<u16>::new());
    drop(held);
}
