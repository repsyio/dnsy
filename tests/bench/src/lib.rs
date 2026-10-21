//! Benchmark tools for DNSY: a closed-loop load generator (`loadgen`), a multi-task fake
//! upstream (`fakeup`), a scenario runner that starts the real server (`bench`, behind
//! `just bench`) and criterion micro-benchmarks (`benches/micro.rs`, `just bench-micro`).
//!
//! Not part of the coverage gate; tests live in `tests/e2e`.

#![expect(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    reason = "benchmark tooling: numeric casts are for statistics and wrapping message ids; helpers panic with a message"
)]

pub mod fakeup;
pub mod load;
