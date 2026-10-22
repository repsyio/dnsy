//! Peak memory of building a one-million-entry filter (performance report 5.9).

use std::fmt::Write as _;
use std::io::Cursor;

use dnsy_filter::{BlockMode, FilterLimits, FilterSetBuilder, ListFormat};

const ENTRIES: usize = 1_000_000;

/// The process high-water mark (`VmHWM`) in KiB, from `/proc/self/status`.
fn high_water_kib() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

#[test]
fn million_entry_build_stays_within_budget() {
    let Some(before) = high_water_kib() else {
        return; // no /proc: nothing to measure on this platform
    };
    let mut body = String::with_capacity(ENTRIES * 24);
    for i in 0..ENTRIES {
        writeln!(body, "ads{i}.tracker{}.example.net", i % 5000).unwrap();
    }
    let list_kib = body.len() / 1024;
    let baseline = high_water_kib().unwrap();
    let mut builder = FilterSetBuilder::new(BlockMode::NxDomain, FilterLimits::default());
    builder.reserve(ENTRIES);
    builder
        .add_list("big", ListFormat::Domains, Cursor::new(body.as_bytes()))
        .unwrap();
    let set = builder.build();
    let after = high_water_kib().unwrap();
    assert_eq!(set.len(), ENTRIES);
    let growth_mib = (after - baseline) / 1024;
    eprintln!(
        "list {} MiB, process before {} MiB, build peak growth {growth_mib} MiB",
        list_kib / 1024,
        before / 1024
    );
    assert!(growth_mib < 60, "build peak grew {growth_mib} MiB");
}
