//! `loadgen --target 127.0.0.1:5353 --proto udp --clients 64 --count 1000`: closed-loop load
//! against any DNS server (UDP or TCP; use `bench` for `DoT` and `DoH`).

use std::net::SocketAddr;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use dnsy_bench::load::{Names, Queries, TcpWorker, UdpWorker, closed_loop};

#[derive(Clone, Copy, ValueEnum)]
enum Proto {
    Udp,
    Tcp,
}

#[derive(Parser)]
struct Args {
    #[arg(long)]
    target: SocketAddr,
    #[arg(long, value_enum, default_value = "udp")]
    proto: Proto,
    #[arg(long, default_value_t = 64)]
    clients: usize,
    /// Queries kept in flight per TCP connection.
    #[arg(long, default_value_t = 1)]
    pipeline: usize,
    /// Distinct names `h<N>.test.`, cycled (cache hits after the first pass).
    #[arg(long, default_value_t = 1000)]
    count: usize,
    /// Every query a unique name (cache misses); overrides `--count`.
    #[arg(long)]
    unique: bool,
    #[arg(long, default_value_t = 3)]
    duration: u64,
    #[arg(long, default_value_t = 1)]
    warmup: u64,
}

#[tokio::main]
async fn main() {
    let a = Args::parse();
    let queries = Queries::new(if a.unique {
        Names::Unique
    } else {
        Names::Cycle(a.count)
    });
    let (warmup, duration) = (
        Duration::from_secs(a.warmup),
        Duration::from_secs(a.duration),
    );
    let mut workers = Vec::new();
    let report = match a.proto {
        Proto::Udp => {
            for c in 0..a.clients {
                workers.push(Some(UdpWorker::connect(a.target, queries.clone(), c).await));
            }
            closed_loop(a.clients, warmup, duration, |c| {
                workers[c].take().expect("worker")
            })
            .await
        }
        Proto::Tcp => {
            let mut tcp = Vec::new();
            for c in 0..a.clients {
                tcp.push(Some(
                    TcpWorker::connect(a.target, queries.clone(), c, a.pipeline).await,
                ));
            }
            closed_loop(a.clients, warmup, duration, |c| {
                tcp[c].take().expect("worker")
            })
            .await
        }
    };
    println!(
        "qps {:.0}  p50 {} us  p99 {} us  errors {}",
        report.qps(),
        report.percentile_us(0.5),
        report.percentile_us(0.99),
        report.errors
    );
}
