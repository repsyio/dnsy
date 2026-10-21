//! `fakeup --bind 127.0.0.1:5399 --tasks 4 --ttl 300`: a fast fake UDP upstream.

use std::net::SocketAddr;

use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:5399")]
    bind: SocketAddr,
    #[arg(long, default_value_t = 4)]
    tasks: usize,
    #[arg(long, default_value_t = 300)]
    ttl: u32,
}

#[tokio::main]
async fn main() {
    let a = Args::parse();
    let (addr, handles) = dnsy_bench::fakeup::start(a.bind, a.tasks, a.ttl).await;
    eprintln!("fakeup listening on {addr}");
    for h in handles {
        let _ = h.await;
    }
}
