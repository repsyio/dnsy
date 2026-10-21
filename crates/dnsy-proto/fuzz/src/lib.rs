//! Fuzz targets and a std-only mutation engine for `dnsy-proto` (and, through
//! `dnsy-dnssec/fuzz`, the validator). The libfuzzer targets in `fuzz_targets/` and the
//! `mutate` binary call the same functions, so a corpus found by either replays in both.

pub mod engine;
pub mod seeds;

use dnsy_proto::{Message, canonical};

/// Everything the decoder, encoder and canonical form do with untrusted bytes. Panics on any
/// broken invariant; returns normally otherwise.
pub fn decode_target(data: &[u8]) {
    let _ = Message::formerr_for(data);
    let Ok(msg) = Message::decode(data) else {
        return;
    };
    for max in [12, 100, 512, 1232, usize::from(u16::MAX)] {
        let _ = msg.encode(max);
        let _ = msg.encode_padded(max);
    }
    let mut with_ede = msg.clone();
    with_ede.set_ede(18, "fuzz");
    let _ = with_ede.encode(usize::from(u16::MAX));
    for r in msg
        .answers
        .iter()
        .chain(&msg.authority)
        .chain(&msg.additional)
    {
        let _ = canonical::rdata_wire(&r.data);
        let _ = r.data.to_string();
    }
    // Anything that decodes must re-encode to something that decodes to the same message,
    // unless the encoder refuses it (oversized rcode, unencodable RDATA).
    if let Ok(wire) = msg.encode(usize::from(u16::MAX)) {
        let again = Message::decode(&wire).expect("re-encoded message decodes");
        assert_eq!(again, msg, "round trip changed the message");
    }
}
