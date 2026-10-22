//! Allocation counts on the cache-hit path (`just allocs`).
//!
//! `unsafe_code` is forbidden workspace-wide, so the repo cannot carry its own counting
//! allocator. The `dhat` crate ships one: this binary installs it as the global allocator and reads
//! the cumulative block count before and after a run. Everything that allocates while a scenario
//! runs is counted, on every thread (listener tasks, the engine, the client side's `send`).
//!
//! Scenarios, each a cache hit for a four-record A answer:
//! - `cache hit`: `Cache::get` alone;
//! - `engine hit`: `Handler::handle` (ACL, rate limit, filters, cache, response shaping);
//! - `udp hit`: a datagram through the UDP listener, the engine and back out, received by a client
//!   using a preallocated buffer.
//!
//! Targets: cache hit <= 2, UDP hit <= 30. With `--check` the exit status is non-zero above them.

#![expect(
    clippy::cast_precision_loss,
    reason = "block counts are far below 2^52; they are averaged as f64"
)]

use std::hint::black_box;
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dnsy_config::Config;
use dnsy_core::{DnssecStatus, SystemClock, Transport};
use dnsy_engine::{EngineBuilder, Handler, RequestContext};
use dnsy_observe::{QueryEvent, QueryEventSink};
use dnsy_proto::{Class, Message, Name, RData, Rcode, Record, RecordType};
use dnsy_resolver::groups::{Exchange, GroupMember, GroupSet, GroupSpec, Strategy, ThreadRng};
use dnsy_resolver::{Cache, CacheKey, CacheOptions, Upstream, UpstreamError};
use dnsy_server::{Server, ServerConfig};
use tokio::net::UdpSocket;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const RUNS: u64 = 2_000;
const CACHE_HIT_TARGET: f64 = 2.0;
const UDP_HIT_TARGET: f64 = 30.0;

fn answer_for(query: &Message) -> Message {
    let mut m = Message::response_to(query);
    m.header.rcode = Rcode::NoError;
    m.answers = (1..=4)
        .map(|i| Record {
            name: Name::from_ascii("www.example.test.").expect("name"),
            rtype: RecordType::A,
            class: Class::In,
            ttl: 300,
            data: RData::A(Ipv4Addr::new(192, 0, 2, i)),
        })
        .collect();
    m
}

struct FakeUp;

impl Exchange for FakeUp {
    fn exchange(
        &self,
        _: &Upstream,
        query: &Message,
    ) -> impl Future<Output = Result<Message, UpstreamError>> + Send {
        std::future::ready(Ok(answer_for(query)))
    }
}

/// Takes the event and drops it, so the cost of building it is on the measured path but no
/// background writer runs.
struct Discard;

impl QueryEventSink for Discard {
    fn record(&self, event: QueryEvent) {
        drop(black_box(event));
    }
}

fn blocks() -> u64 {
    dhat::HeapStats::get().total_blocks
}

/// Allocations per run of `f`, after `RUNS / 10` warm-up runs.
fn per_run(mut f: impl FnMut()) -> f64 {
    for _ in 0..RUNS / 10 {
        f();
    }
    let before = blocks();
    for _ in 0..RUNS {
        f();
    }
    (blocks() - before) as f64 / RUNS as f64
}

fn query() -> Message {
    let mut q = dnsy_e2e::query("www.example.test.", RecordType::A);
    q.header.id = 0x1234;
    q
}

fn engine() -> Arc<dnsy_engine::Engine<FakeUp>> {
    let groups = GroupSet::new(
        vec![GroupSpec {
            name: "default".to_owned(),
            strategy: Strategy::Failover,
            default: true,
            domains: vec![],
            members: vec![GroupMember {
                upstream: "udp://192.0.2.1:53".parse().expect("upstream"),
                weight: 1,
            }],
        }],
        Arc::new(SystemClock),
        Arc::new(ThreadRng),
    )
    .expect("groups");
    Arc::new(
        EngineBuilder::new(&Config::default(), FakeUp)
            .groups(groups)
            .rate_limit(0)
            .sink(Arc::new(Discard))
            .build(),
    )
}

fn context() -> RequestContext {
    RequestContext {
        client: ([127, 0, 0, 1], 40000).into(),
        transport: Transport::Udp,
        principal: None,
        received_at: Instant::now(),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let check = std::env::args().any(|a| a == "--check");
    let _profiler = dhat::Profiler::builder().testing().build();

    // Cache::get alone.
    let cache = Cache::new(CacheOptions::default());
    let now = Instant::now();
    let q = query();
    let key = CacheKey {
        name: q.questions[0].name.clone(),
        qtype: RecordType::A,
        qclass: Class::In,
        do_bit: false,
        cd_bit: false,
    };
    cache.insert(key.clone(), answer_for(&q), DnssecStatus::Insecure, now);
    let cache_hit = per_run(|| {
        black_box(cache.get(black_box(&key), now));
    });

    // Handler::handle on a warm cache.
    let engine = engine();
    let warm = engine.handle(context(), &q).await;
    assert_eq!(warm.answers.len(), 4);
    let (mut ctx, mut count) = (context(), 0u64);
    for _ in 0..RUNS / 10 {
        black_box(engine.handle(ctx.clone(), &q).await);
    }
    let before = blocks();
    for _ in 0..RUNS {
        ctx.received_at = Instant::now();
        black_box(engine.handle(ctx.clone(), &q).await);
        count += 1;
    }
    let engine_hit = (blocks() - before) as f64 / count as f64;

    // A datagram through the UDP listener (warm cache: the engine above shares it).
    let lo = (Ipv4Addr::LOCALHOST, 0).into();
    let server = Server::start(ServerConfig::new(vec![lo], vec![lo]), Arc::clone(&engine))
        .await
        .expect("server");
    let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    sock.connect(server.udp_addrs()[0]).await.expect("connect");
    let wire = q.encode(512).expect("encode");
    let mut buf = vec![0u8; 4096];
    let mut round = async || {
        sock.send(&wire).await.expect("send");
        let n = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf))
            .await
            .expect("reply in time")
            .expect("recv");
        black_box(n);
    };
    for _ in 0..RUNS / 10 {
        round().await;
    }
    let before = blocks();
    for _ in 0..RUNS {
        round().await;
    }
    let udp_hit = (blocks() - before) as f64 / RUNS as f64;
    server.shutdown().await;

    println!("{:<12} {:>10} {:>8}", "scenario", "allocs/op", "target");
    println!(
        "{:<12} {cache_hit:>10.2} {CACHE_HIT_TARGET:>8}",
        "cache hit"
    );
    println!("{:<12} {engine_hit:>10.2} {:>8}", "engine hit", "-");
    println!("{:<12} {udp_hit:>10.2} {UDP_HIT_TARGET:>8}", "udp hit");
    if check && (cache_hit > CACHE_HIT_TARGET || udp_hit > UDP_HIT_TARGET) {
        eprintln!("allocation target exceeded");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
