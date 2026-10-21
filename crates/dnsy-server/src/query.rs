//! Transport-independent query parsing and UDP sizing.

use dnsy_proto::{Edns, EdnsOption, Message, PADDING_BLOCK, Rcode};

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

/// Pads `response` with an EDNS Padding option so its encoded size is a multiple of
/// [`PADDING_BLOCK`] (RFC 8467 section 4.1). Adds the OPT record when missing; no-op if the response cannot encode.
pub(crate) fn pad_response(response: &mut Message) {
    let edns = response.edns.get_or_insert_with(Edns::default);
    edns.options
        .retain(|o| !matches!(o, EdnsOption::Padding(_)));
    let Ok(len) = response.encode(usize::from(u16::MAX)).map(|b| b.len()) else {
        return;
    };
    let rem = len % PADDING_BLOCK;
    if rem == 0 {
        return;
    }
    let mut need = PADDING_BLOCK - rem;
    if need < 4 {
        need += PADDING_BLOCK; // an option header alone takes 4 octets
    }
    if let Some(edns) = response.edns.as_mut()
        && let Ok(n) = u16::try_from(need - 4)
    {
        edns.options.push(EdnsOption::Padding(n));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnsy_proto::{Class, Header, Name, Opcode, Question, RecordType};

    fn query(questions: usize, edns: Option<Edns>) -> Message {
        Message {
            header: Header {
                id: 0x1234,
                qr: false,
                opcode: Opcode::Query,
                aa: false,
                tc: false,
                rd: true,
                ra: false,
                ad: false,
                cd: false,
                rcode: Rcode::NoError,
            },
            questions: (0..questions)
                .map(|_| Question {
                    name: Name::from_ascii("example.com").unwrap(),
                    qtype: RecordType::A,
                    qclass: Class::In,
                })
                .collect(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            edns,
        }
    }

    fn wire(m: &Message) -> Vec<u8> {
        m.encode(4096).unwrap()
    }

    #[test]
    fn well_formed_query_is_accepted() {
        assert!(matches!(parse(&wire(&query(1, None))), Incoming::Query(_)));
    }

    #[test]
    fn responses_are_never_answered() {
        let mut m = query(1, None);
        m.header.qr = true;
        assert!(matches!(parse(&wire(&m)), Incoming::Drop));
    }

    #[test]
    fn garbage_shorter_than_a_header_is_dropped() {
        assert!(matches!(parse(&[1, 2, 3]), Incoming::Drop));
        assert!(matches!(parse(&[]), Incoming::Drop));
    }

    #[test]
    fn truncated_body_with_readable_header_gets_formerr_with_same_id() {
        let mut bytes = wire(&query(1, None));
        bytes.truncate(14);
        let Incoming::Reply(reply) = parse(&bytes) else {
            panic!("expected FORMERR reply");
        };
        let m = Message::decode(&reply).unwrap();
        assert_eq!(m.header.id, 0x1234);
        assert!(m.header.qr);
        assert_eq!(m.header.rcode, Rcode::FormErr);
    }

    #[test]
    fn zero_or_many_questions_get_formerr_without_edns() {
        for n in [0, 2] {
            let q = query(n, Some(Edns::default()));
            let Incoming::Reply(reply) = parse(&wire(&q)) else {
                panic!("expected FORMERR for {n} questions");
            };
            let m = Message::decode(&reply).unwrap();
            assert_eq!(m.header.rcode, Rcode::FormErr);
            assert!(m.edns.is_none());
        }
    }

    #[test]
    fn udp_limit_follows_edns_within_bounds() {
        assert_eq!(udp_limit(&query(1, None)), MIN_UDP_PAYLOAD);
        let with = |p| {
            udp_limit(&query(
                1,
                Some(Edns {
                    udp_payload: p,
                    ..Edns::default()
                }),
            ))
        };
        assert_eq!(with(100), MIN_UDP_PAYLOAD);
        assert_eq!(with(1400), 1400_usize.min(MAX_UDP_PAYLOAD));
        assert_eq!(with(u16::MAX), MAX_UDP_PAYLOAD);
    }

    #[test]
    fn encode_response_falls_back_to_servfail_when_too_big() {
        let q = query(1, None);
        let mut r = Message::response_to(&q);
        for i in 0..40 {
            r.answers.push(dnsy_proto::Record {
                name: Name::from_ascii(&format!("host{i}.example.com")).unwrap(),
                rtype: RecordType::A,
                class: Class::In,
                ttl: 60,
                data: dnsy_proto::RData::A([192, 0, 2, 1].into()),
            });
        }
        // A limit below the header+question size cannot hold the answer; if even SERVFAIL
        // cannot fit, there is no reply at all.
        assert!(encode_response(&q, &r, 12).is_none());
        let bytes = encode_response(&q, &r, 512).unwrap();
        assert!(bytes.len() <= 512);
    }

    #[test]
    fn padding_reaches_a_block_multiple_and_replaces_existing_padding() {
        let q = query(1, None);
        let mut r = Message::response_to(&q);
        r.edns = Some(Edns {
            options: vec![EdnsOption::Padding(7)],
            ..Edns::default()
        });
        pad_response(&mut r);
        let len = r.encode(u16::MAX.into()).unwrap().len();
        assert_eq!(len % PADDING_BLOCK, 0);
        let paddings = r
            .edns
            .as_ref()
            .unwrap()
            .options
            .iter()
            .filter(|o| matches!(o, EdnsOption::Padding(_)))
            .count();
        assert_eq!(paddings, 1);
        // Idempotent: padding an already padded response keeps the size.
        pad_response(&mut r);
        assert_eq!(r.encode(u16::MAX.into()).unwrap().len(), len);
    }
}
