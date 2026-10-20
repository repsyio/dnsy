//! `cargo +nightly fuzz run fuzz_decode` from `crates/dnsy-proto/`.
#![no_main]

use dnsy_proto::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Message::formerr_for(data);
    if let Ok(msg) = Message::decode(data) {
        // Anything that decodes must re-encode to something that decodes again.
        if let Ok(wire) = msg.encode(usize::from(u16::MAX)) {
            Message::decode(&wire).expect("re-encoded message decodes");
        }
    }
});
