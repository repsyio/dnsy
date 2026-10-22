//! Micro-benchmarks: DNS codec and cache lookup (`just bench-micro`).

use std::hint::black_box;
use std::time::Instant;

use criterion::{Criterion, criterion_group, criterion_main};
use dnsy_core::DnssecStatus;
use dnsy_proto::{Class, Message, Name, RData, Rcode, Record, RecordType};
use dnsy_resolver::CacheOptions;
use dnsy_resolver::{Cache, CacheKey};

const THREADS: usize = 16;
const PER_THREAD: usize = 20_000;

fn response() -> Message {
    let mut m = dnsy_e2e::query("www.example.test.", RecordType::A);
    m.header.qr = true;
    m.header.rcode = Rcode::NoError;
    m.answers = (1..=4)
        .map(|i| Record {
            name: Name::from_ascii("www.example.test.").expect("name"),
            rtype: RecordType::A,
            class: Class::In,
            ttl: 300,
            data: RData::A(std::net::Ipv4Addr::new(192, 0, 2, i)),
        })
        .collect();
    m
}

fn codec(c: &mut Criterion) {
    let m = response();
    let wire = m.encode(512).expect("encode");
    c.bench_function("codec/decode", |b| {
        b.iter(|| Message::decode(black_box(&wire)));
    });
    c.bench_function("codec/encode", |b| b.iter(|| black_box(&m).encode(512)));
}

fn cache(c: &mut Criterion) {
    let cache = Cache::new(CacheOptions::default());
    let now = Instant::now();
    let key = CacheKey {
        name: Name::from_ascii("www.example.test.").expect("name"),
        qtype: RecordType::A,
        qclass: Class::In,
        do_bit: false,
        cd_bit: false,
    };
    cache.insert(key.clone(), response(), DnssecStatus::Insecure, now);
    c.bench_function("cache/hit", |b| b.iter(|| cache.get(black_box(&key), now)));

    // The same hit from 16 threads over 1000 names; criterion reports the time for one pass of
    // `THREADS * PER_THREAD` lookups, so ops/s = lookups / time.
    let keys: Vec<CacheKey> = (0..1000)
        .map(|i| CacheKey {
            name: Name::from_ascii(&format!("h{i}.example.test.")).expect("name"),
            ..key.clone()
        })
        .collect();
    for k in &keys {
        cache.insert(k.clone(), response(), DnssecStatus::Insecure, now);
    }
    c.bench_function("cache/hit_16_threads_320k", |b| {
        b.iter(|| {
            std::thread::scope(|s| {
                for t in 0..THREADS {
                    let (cache, keys) = (&cache, &keys);
                    s.spawn(move || {
                        for i in 0..PER_THREAD {
                            black_box(cache.get(&keys[(t * 31 + i) % keys.len()], now));
                        }
                    });
                }
            });
        });
    });
}

criterion_group!(benches, codec, cache);
criterion_main!(benches);
