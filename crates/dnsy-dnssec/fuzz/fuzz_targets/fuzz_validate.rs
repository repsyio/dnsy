//! `just fuzz fuzz_validate 3600` (nightly) runs this from `crates/dnsy-dnssec/`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dnsy_dnssec_fuzz::validate_target(data));
