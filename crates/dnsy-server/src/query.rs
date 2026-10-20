//! Transport-independent query parsing and UDP sizing.

use dnsy_proto::{Message, Rcode};

/// Largest UDP response we send, whatever the client advertises (avoids fragmentation).
pub const MAX_UDP_PAYLOAD: usize = 1232;
/// UDP response limit without EDNS (RFC 1035).
pub const MIN_UDP_PAYLOAD: usize = 512;

/// What to do with an incoming packet.
pub(crate) enum Incoming {
    Query(Message),
    /// Send these bytes back (a minimal FORMERR).
    Reply(Vec<u8>),
    Drop,
}

/// Decodes a query. Malformed packets get a FORMERR when the header is readable and are dropped
/// otherwise; packets that are themselves responses are always dropped.
pub(crate) fn parse(buf: &[u8]) -> Incoming {
    match Message::decode(buf) {
        Err(_) => Message::formerr_for(buf).map_or(Incoming::Drop, Incoming::Reply),
        Ok(query) if query.header.qr => Incoming::Drop,
        Ok(query) if query.questions.len() != 1 => {
            let mut response = Message::response_to(&query);
            response.header.rcode = Rcode::FormErr;
            response.edns = None;
            response
                .encode(MIN_UDP_PAYLOAD)
                .map_or(Incoming::Drop, Incoming::Reply)
        }
        Ok(query) => Incoming::Query(query),
    }
}

/// UDP payload limit for the answer to `query`.
pub(crate) fn udp_limit(query: &Message) -> usize {
    query.edns.as_ref().map_or(MIN_UDP_PAYLOAD, |e| {
        usize::from(e.udp_payload).clamp(MIN_UDP_PAYLOAD, MAX_UDP_PAYLOAD)
    })
}

/// Encodes `response` within `limit`, falling back to a bare SERVFAIL if encoding fails.
pub(crate) fn encode_response(
    query: &Message,
    response: &Message,
    limit: usize,
) -> Option<Vec<u8>> {
    response.encode(limit).ok().or_else(|| {
        let mut failure = Message::response_to(query);
        failure.header.rcode = Rcode::ServFail;
        failure.encode(limit).ok()
    })
}
