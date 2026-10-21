//! Closed-loop load generation: N clients, each sends a query, waits for the answer, repeats.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dnsy_proto::{Message, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};

/// Which names the clients ask for.
#[derive(Debug, Clone, Copy)]
pub enum Names {
    /// `h0.test.` .. `h{count-1}.test.`, cycled: after the first pass every query is a cache hit.
    Cycle(usize),
    /// `u<n>.test.` with a process-wide counter: every query is a cache miss.
    Unique,
}

/// Pre-encoded query wires for `names`; the id is patched per send.
#[derive(Clone)]
pub struct Queries {
    wires: Arc<Vec<Vec<u8>>>,
    unique: bool,
}

fn wire_for(name: &str) -> Vec<u8> {
    dnsy_e2e::clients::wire(&dnsy_e2e::query(name, RecordType::A))
}

impl Queries {
    pub fn new(names: Names) -> Queries {
        match names {
            Names::Cycle(n) => Queries {
                wires: Arc::new(
                    (0..n.max(1))
                        .map(|i| wire_for(&format!("h{i}.test.")))
                        .collect(),
                ),
                unique: false,
            },
            Names::Unique => Queries {
                wires: Arc::new(Vec::new()),
                unique: true,
            },
        }
    }

    /// The `i`-th query of a client, with `id` as message id.
    fn get(&self, client: usize, i: usize, id: u16) -> Vec<u8> {
        let mut w = if self.unique {
            wire_for(&format!("u{client}x{i}.test."))
        } else {
            self.wires[(i + client * 7) % self.wires.len()].clone()
        };
        w[..2].copy_from_slice(&id.to_be_bytes());
        w
    }
}

/// Result of one run.
#[derive(Debug, Clone)]
pub struct Report {
    pub exchanges: u64,
    pub errors: u64,
    pub elapsed: Duration,
    latencies_us: Vec<u32>,
}

impl Report {
    pub fn qps(&self) -> f64 {
        self.exchanges as f64 / self.elapsed.as_secs_f64()
    }

    /// Latency percentile (`0.5`, `0.99`) per exchange, in microseconds.
    pub fn percentile_us(&self, p: f64) -> u32 {
        if self.latencies_us.is_empty() {
            return 0;
        }
        let idx = ((self.latencies_us.len() - 1) as f64 * p).round() as usize;
        self.latencies_us[idx]
    }
}

/// One client: `one` does a single request/answer exchange and says whether it worked.
pub trait Worker: Send + 'static {
    fn one(&mut self, i: usize) -> impl Future<Output = bool> + Send;
}

/// Runs `clients` workers for `warmup` (discarded) and then `duration`.
pub async fn closed_loop<W: Worker>(
    clients: usize,
    warmup: Duration,
    duration: Duration,
    mut make: impl FnMut(usize) -> W,
) -> Report {
    let start = Instant::now();
    let measure_from = start + warmup;
    let end = measure_from + duration;
    let mut tasks = Vec::with_capacity(clients);
    for c in 0..clients {
        let mut worker = make(c);
        tasks.push(tokio::spawn(async move {
            let (mut lat, mut errors, mut i) = (Vec::new(), 0_u64, 0_usize);
            loop {
                let t0 = Instant::now();
                if t0 >= end {
                    break;
                }
                let ok = worker.one(i).await;
                i += 1;
                if t0 < measure_from {
                    continue;
                }
                if ok {
                    lat.push(u32::try_from(t0.elapsed().as_micros()).unwrap_or(u32::MAX));
                } else {
                    errors += 1;
                }
            }
            (lat, errors)
        }));
    }
    let mut latencies_us = Vec::new();
    let mut errors = 0;
    for t in tasks {
        let (lat, e) = t.await.expect("worker task");
        latencies_us.extend(lat);
        errors += e;
    }
    latencies_us.sort_unstable();
    Report {
        exchanges: latencies_us.len() as u64,
        errors,
        elapsed: duration,
        latencies_us,
    }
}

/// A UDP client with its own connected socket.
pub struct UdpWorker {
    socket: UdpSocket,
    queries: Queries,
    client: usize,
    buf: Vec<u8>,
}

impl UdpWorker {
    pub async fn connect(target: SocketAddr, queries: Queries, client: usize) -> UdpWorker {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        socket.connect(target).await.expect("connect udp");
        UdpWorker {
            socket,
            queries,
            client,
            buf: vec![0; 4096],
        }
    }
}

impl Worker for UdpWorker {
    async fn one(&mut self, i: usize) -> bool {
        let id = (i & 0xFFFF) as u16;
        let q = self.queries.get(self.client, i, id);
        if self.socket.send(&q).await.is_err() {
            return false;
        }
        match tokio::time::timeout(Duration::from_secs(1), self.socket.recv(&mut self.buf)).await {
            Ok(Ok(n)) => n >= 2 && self.buf[..2] == id.to_be_bytes(),
            _ => false,
        }
    }
}

/// A TCP client keeping `pipeline` queries in flight (1 = strictly sequential). One exchange is
/// one answer read plus one query sent, so per-exchange latency is per query only at pipeline 1.
pub struct TcpWorker {
    stream: BufReader<TcpStream>,
    queries: Queries,
    client: usize,
    pipeline: usize,
    sent: usize,
}

impl TcpWorker {
    pub async fn connect(
        target: SocketAddr,
        queries: Queries,
        client: usize,
        pipeline: usize,
    ) -> TcpWorker {
        let stream = TcpStream::connect(target).await.expect("connect tcp");
        stream.set_nodelay(true).expect("nodelay");
        TcpWorker {
            stream: BufReader::new(stream),
            queries,
            client,
            pipeline: pipeline.max(1),
            sent: 0,
        }
    }

    async fn send_next(&mut self) -> bool {
        let id = (self.sent & 0xFFFF) as u16;
        let q = self.queries.get(self.client, self.sent, id);
        self.sent += 1;
        let mut frame = Vec::with_capacity(q.len() + 2);
        frame.extend_from_slice(&u16::try_from(q.len()).expect("frame").to_be_bytes());
        frame.extend_from_slice(&q);
        self.stream.get_mut().write_all(&frame).await.is_ok()
    }
}

impl Worker for TcpWorker {
    async fn one(&mut self, i: usize) -> bool {
        if i == 0 {
            for _ in 1..self.pipeline {
                if !self.send_next().await {
                    return false;
                }
            }
        }
        if !self.send_next().await {
            return false;
        }
        let mut len = [0_u8; 2];
        if self.stream.read_exact(&mut len).await.is_err() {
            return false;
        }
        let mut body = vec![0_u8; usize::from(u16::from_be_bytes(len))];
        self.stream.read_exact(&mut body).await.is_ok() && Message::decode(&body).is_ok()
    }
}
