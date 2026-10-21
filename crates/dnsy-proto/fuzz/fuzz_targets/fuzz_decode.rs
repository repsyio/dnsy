//! `just fuzz fuzz_decode 3600` (nightly) runs this from `crates/dnsy-proto/`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dnsy_proto_fuzz::decode_target(data));
