//! `cargo run --release --bin mutate -- <seconds> [seed] [corpus-dir]` from
//! `crates/dnsy-dnssec/fuzz/` (stable toolchain); crashing inputs land in `crashes/`.

use std::path::PathBuf;

fn main() {
    let mut args = std::env::args().skip(1);
    let seconds: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(60);
    let seed: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(1);
    let corpus = PathBuf::from(args.next().unwrap_or_else(|| "corpus/fuzz_validate".into()));

    let mut seeds = dnsy_dnssec_fuzz::seeds();
    if std::env::var_os("DNSY_FUZZ_WRITE_SEEDS").is_some() {
        // Writes the built-in seeds into the corpus directory (how the committed corpus started).
        std::fs::create_dir_all(&corpus).expect("create corpus dir");
        for (i, s) in seeds.iter().enumerate() {
            std::fs::write(corpus.join(format!("seed-{i:02}")), s).expect("write seed");
        }
        return;
    }
    if let Ok(dir) = std::fs::read_dir(&corpus) {
        seeds.extend(dir.flatten().filter_map(|e| std::fs::read(e.path()).ok()));
    }
    let report =
        dnsy_proto_fuzz::engine::run(&seeds, seconds, seed, &PathBuf::from("crashes"), |d| {
            dnsy_dnssec_fuzz::validate_target(d);
        });
    println!(
        "fuzz_validate: {} iterations, {} panics, {} seeds, {seconds} s",
        report.iterations,
        report.panics,
        seeds.len()
    );
    std::process::exit(i32::from(report.panics > 0));
}
