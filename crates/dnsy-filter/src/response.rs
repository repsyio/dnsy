//! Synthesised answers for blocked queries.

use dnsy_proto::{Class, Message, RData, Rcode, Record, RecordType, ede};

use crate::matcher::{BlockMode, CUSTOM_LIST};

/// TTL of synthesised sinkhole answers.
pub const BLOCK_TTL: u32 = 60;

/// Builds the response for a blocked `query`.
///
/// The Extended DNS Error is attached only when the client sent EDNS: code 15 (blocked) for list
/// matches, 17 (filtered) for operator custom rules. Returns `None` when the query has no
/// question.
#[must_use]
pub fn block_response(query: &Message, mode: BlockMode, list: &str) -> Option<Message> {
    let question = query.questions.first()?;
    let mut response = Message::response_to(query);
    response.header.ra = true;
    match mode {
        BlockMode::NxDomain => response.header.rcode = Rcode::NxDomain,
        BlockMode::Refused => response.header.rcode = Rcode::Refused,
        BlockMode::NullIp | BlockMode::CustomIp { .. } => {
            let (v4, v6) = match mode {
                BlockMode::CustomIp { v4, v6 } => (v4, v6),
                _ => (Some([0; 4].into()), Some([0; 16].into())),
            };
            let data = match question.qtype {
                RecordType::A => v4.map(RData::A),
                RecordType::Aaaa => v6.map(RData::Aaaa),
                _ => None,
            };
            if let (Some(data), Class::In) = (data, question.qclass) {
                response.answers.push(Record {
                    name: question.name.clone(),
                    rtype: question.qtype,
                    class: Class::In,
                    ttl: BLOCK_TTL,
                    data,
                });
            }
        }
    }
    if query.edns.is_some() {
        if list == CUSTOM_LIST {
            response.set_ede(ede::FILTERED, "filtered");
        } else {
            response.set_ede(ede::BLOCKED, "blocked");
        }
    }
    Some(response)
}
