//! A small deterministic mutation fuzzer: no dependencies, no coverage feedback. It is what
//! runs on the pinned stable toolchain when `cargo fuzz` (nightly) is not available.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::time::{Duration, Instant};

/// xorshift64* generator.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n.max(1)).unwrap_or(1)).unwrap_or(0)
    }
}

const INTERESTING: &[&[u8]] = &[
    &[0x00],
    &[0xFF],
    &[0xC0],
    &[0x3F],
    &[0x40],
    &[0x80],
    &[0x7F],
    &[0x00, 0x00],
    &[0xFF, 0xFF],
    &[0xC0, 0x0C],
    &[0xC0, 0x00],
    &[0x00, 0x29],
    &[0x00, 0x2F],
    &[0x00, 0x32],
    &[0x00, 0x01, 0x00, 0x00],
    &[0x7F, 0xFF, 0xFF, 0xFF],
    &[0xFF, 0xFF, 0xFF, 0xFF],
];

/// One to four stacked mutations of `input`, optionally splicing from `other`.
pub fn mutate(rng: &mut Rng, input: &[u8], other: &[u8]) -> Vec<u8> {
    let mut v = input.to_vec();
    for _ in 0..=rng.below(4) {
        match rng.below(10) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = u8::try_from(rng.next() & 0xFF).unwrap_or(0);
            }
            2 if !v.is_empty() => {
                let pat = INTERESTING[rng.below(INTERESTING.len())];
                let i = rng.below(v.len());
                for (k, b) in pat.iter().enumerate() {
                    if let Some(slot) = v.get_mut(i + k) {
                        *slot = *b;
                    }
                }
            }
            3 => {
                let pat = INTERESTING[rng.below(INTERESTING.len())];
                let i = rng.below(v.len() + 1);
                v.splice(i..i, pat.iter().copied());
            }
            4 if !v.is_empty() => {
                let i = rng.below(v.len());
                let n = 1 + rng.below(8.min(v.len() - i));
                v.drain(i..i + n);
            }
            5 if !v.is_empty() => {
                let i = rng.below(v.len());
                let n = 1 + rng.below(16.min(v.len() - i));
                let chunk = v[i..i + n].to_vec();
                let at = rng.below(v.len() + 1);
                v.splice(at..at, chunk);
            }
            6 => {
                let keep = rng.below(v.len() + 1);
                v.truncate(keep);
            }
            7 if !other.is_empty() => {
                let a = rng.below(other.len());
                let n = 1 + rng.below((other.len() - a).min(32));
                let at = rng.below(v.len() + 1);
                v.splice(at..at, other[a..a + n].iter().copied());
            }
            8 if v.len() >= 2 => {
                // 16-bit field nudged by a small delta (counts, lengths, pointers)
                let i = rng.below(v.len() - 1);
                let x = u16::from_be_bytes([v[i], v[i + 1]]);
                let d = u16::try_from(rng.below(5)).unwrap_or(0).wrapping_sub(2);
                v[i..i + 2].copy_from_slice(&x.wrapping_add(d).to_be_bytes());
            }
            _ => {
                let n = rng.below(64);
                v = (0..n)
                    .map(|_| u8::try_from(rng.next() & 0xFF).unwrap_or(0))
                    .collect();
            }
        }
        v.truncate(1 << 17);
    }
    v
}

/// Totals of one run.
#[derive(Debug, Default)]
pub struct Report {
    pub iterations: u64,
    pub panics: u64,
}

/// Mutates `seeds` for `seconds`, calling `target` on every input under `catch_unwind`.
/// A panicking input is written to `crash_dir`. Every input is a mutation of a seed, a fresh
/// random buffer (1 in 8) or a mutation of a recent mutation (1 in 4).
pub fn run(
    seeds: &[Vec<u8>],
    seconds: u64,
    rng_seed: u64,
    crash_dir: &Path,
    target: impl Fn(&[u8]),
) -> Report {
    let mut rng = Rng::new(rng_seed);
    let mut report = Report::default();
    let end = Instant::now() + Duration::from_secs(seconds);
    let mut last = seeds.first().cloned().unwrap_or_default();
    std::panic::set_hook(Box::new(|_| {}));
    while Instant::now() < end {
        for _ in 0..4096 {
            let base = &seeds[rng.below(seeds.len())];
            let other = &seeds[rng.below(seeds.len())];
            let input = match rng.below(8) {
                0 => (0..rng.below(600))
                    .map(|_| u8::try_from(rng.next() & 0xFF).unwrap_or(0))
                    .collect(),
                1 | 2 => mutate(&mut rng, &last, other),
                _ => mutate(&mut rng, base, other),
            };
            report.iterations += 1;
            if catch_unwind(AssertUnwindSafe(|| target(&input))).is_err() {
                report.panics += 1;
                let _ = std::fs::create_dir_all(crash_dir);
                let name = format!("crash-{}-{}", rng_seed, report.iterations);
                let _ = std::fs::write(crash_dir.join(name), &input);
            }
            last = input;
        }
    }
    let _ = std::panic::take_hook();
    report
}
