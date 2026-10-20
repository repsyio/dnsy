//! Embeds the build timestamp (Unix seconds; `SOURCE_DATE_EPOCH` for reproducible builds). The
//! DNSSEC clock-sanity check (DNSY-37) treats a system clock earlier than this as untrusted.

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let stamp = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs())
        })
        .unwrap_or(0);
    println!("cargo:rustc-env=DNSY_BUILD_TIME={stamp}");
    if std::env::var_os("CARGO_FEATURE_EMBED_UI").is_some() {
        println!("cargo:rerun-if-changed=../../web/dist");
        if !std::path::Path::new("../../web/dist/dnsy/browser/index.html").exists() {
            println!(
                "cargo:warning=feature embed-ui needs web/dist; run `just build` (builds the UI first)"
            );
        }
    }
}
