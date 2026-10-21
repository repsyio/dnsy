//! Scenario runner behind `just bench`: starts the real `dnsy` binary (`DNSY_BIN`) with a fast
//! fake upstream and prints UDP cache-hit, UDP cache-miss, TCP and `DoH` numbers.

use std::time::Duration;

use dnsy_bench::load::{Names, Queries, Report, TcpWorker, UdpWorker, Worker, closed_loop};
use dnsy_e2e::upstream::a;
use dnsy_e2e::{DohClient, FakeUpstream, Harness, Opts, Reply, Token, query};
use dnsy_proto::RecordType;

const WARMUP: Duration = Duration::from_secs(1);
const RUN: Duration = Duration::from_secs(3);

struct DohWorker {
    client: std::sync::Arc<DohClient>,
    token: Token,
    client_id: usize,
}

impl Worker for DohWorker {
    async fn one(&mut self, i: usize) -> bool {
        let q = query(
            &format!("h{}.test.", (i + self.client_id * 7) % 1000),
            RecordType::A,
        );
        self.client.post(&q, &self.token).await.status == 200
    }
}

fn row(name: &str, clients: usize, r: &Report) {
    println!(
        "{name:<34} {clients:>7} {:>10.0} {:>9} {:>9} {:>6}",
        r.qps(),
        r.percentile_us(0.5),
        r.percentile_us(0.99),
        r.errors
    );
}

#[tokio::main]
async fn main() {
    let up = FakeUpstream::start().await;
    up.set_responder(std::sync::Arc::new(|name, _, _| {
        Some(Reply::Answer(vec![a(&name.to_string(), 300, "192.0.2.1")]))
    }));
    let opts = Opts {
        doh: true,
        doh_require_token: false,
        log_level: "warn",
        ..Opts::default()
    };
    let h = Harness::start_with(opts, Some(up)).await;

    println!(
        "{:<34} {:>7} {:>10} {:>9} {:>9} {:>6}",
        "scenario", "clients", "qps", "p50 us", "p99 us", "errors"
    );
    let hit = Queries::new(Names::Cycle(1000));
    let miss = Queries::new(Names::Unique);

    let mut udp = Vec::new();
    for c in 0..64 {
        udp.push(Some(UdpWorker::connect(h.udp, hit.clone(), c).await));
    }
    row(
        "udp cache hit",
        64,
        &closed_loop(64, WARMUP, RUN, |c| udp[c].take().expect("w")).await,
    );

    let mut udp = Vec::new();
    for c in 0..64 {
        udp.push(Some(UdpWorker::connect(h.udp, miss.clone(), c).await));
    }
    row(
        "udp cache miss",
        64,
        &closed_loop(64, WARMUP, RUN, |c| udp[c].take().expect("w")).await,
    );

    for (name, clients, pipeline) in [
        ("tcp persistent (pipeline 1)", 1, 1),
        ("tcp pipeline 1", 64, 1),
        ("tcp pipeline 16", 64, 16),
    ] {
        let mut tcp = Vec::new();
        for c in 0..clients {
            tcp.push(Some(
                TcpWorker::connect(h.tcp, hit.clone(), c, pipeline).await,
            ));
        }
        row(
            name,
            clients,
            &closed_loop(clients, WARMUP, RUN, |c| tcp[c].take().expect("w")).await,
        );
    }

    for (name, http2) in [("doh http/1.1 POST", false), ("doh h2 POST", true)] {
        let client = std::sync::Arc::new(h.doh_client(http2));
        let r = closed_loop(64, WARMUP, RUN, |c| DohWorker {
            client: client.clone(),
            token: Token::None,
            client_id: c,
        })
        .await;
        row(name, 64, &r);
    }
}
