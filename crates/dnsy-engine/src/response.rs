//! Building and shaping responses: authoritative answers, upstream scrubbing (bailiwick and
//! minimal responses), error responses and the response-IP policy.

use std::net::IpAddr;

use dnsy_proto::{
    Class, Edns, EdnsOption, Message, Name, Question, RData, Rcode, Record, RecordType,
};
use dnsy_zone::{LookupResult, ZoneSet};
use ipnet::IpNet;

/// Most CNAMEs followed when tracing a chain through an answer section.
const MAX_CHAIN: usize = 16;

/// Blocklist name reported when the response-IP policy blocks an answer.
pub const RESPONSE_IP_LIST: &str = "response-ip";

/// Answers whose A/AAAA records fall inside any of these networks are blocked.
#[derive(Debug, Clone, Default)]
pub struct ResponseIpPolicy {
    nets: Vec<IpNet>,
}

impl ResponseIpPolicy {
    #[must_use]
    pub fn new(nets: impl IntoIterator<Item = IpNet>) -> Self {
        Self {
            nets: nets.into_iter().map(|n| n.trunc()).collect(),
        }
    }

    /// True when an address record in the answer section is listed.
    #[must_use]
    pub fn blocks(&self, msg: &Message) -> bool {
        if self.nets.is_empty() {
            return false;
        }
        msg.answers.iter().any(|r| {
            let ip = match r.data {
                RData::A(v4) => IpAddr::V4(v4),
                RData::Aaaa(v6) => IpAddr::V6(v6).to_canonical(),
                _ => return false,
            };
            self.nets.iter().any(|n| n.contains(&ip))
        })
    }
}

/// Whether the query asked for DNSSEC records (EDNS DO bit).
pub(crate) fn dnssec_ok(query: &Message) -> bool {
    query.edns.as_ref().is_some_and(|e| e.dnssec_ok)
}

/// An empty response with `rcode`, carrying an Extended DNS Error when the client sent EDNS.
pub(crate) fn error_response(query: &Message, rcode: Rcode, ede: Option<(u16, &str)>) -> Message {
    let mut response = Message::response_to(query);
    response.header.rcode = rcode;
    if let Some((code, text)) = ede
        && query.edns.is_some()
    {
        response.set_ede(code, text);
    }
    response
}

/// Final shaping for the client: the client's id, flags and question (preserving its name case),
/// RA set, and an OPT record only when the client sent one, carrying our payload size, the
/// client's DO bit and only the Extended DNS Error options of `msg`.
pub(crate) fn finish(query: &Message, mut msg: Message) -> Message {
    msg.header.id = query.header.id;
    msg.header.qr = true;
    msg.header.opcode = query.header.opcode;
    msg.header.rd = query.header.rd;
    msg.header.cd = query.header.cd;
    msg.header.ra = true;
    msg.questions.clone_from(&query.questions);
    msg.edns = query.edns.as_ref().map(|q| Edns {
        dnssec_ok: q.dnssec_ok,
        options: msg
            .edns
            .take()
            .map(|e| {
                e.options
                    .into_iter()
                    .filter(|o| matches!(o, EdnsOption::ExtendedError { .. }))
                    .collect()
            })
            .unwrap_or_default(),
        ..Edns::default()
    });
    msg
}

/// The names of the CNAME chain starting at `qname` (`qname` first, the final target last).
fn chain(qname: &Name, qtype: RecordType, answers: &[Record]) -> Vec<Name> {
    let mut names = vec![qname.clone()];
    if matches!(qtype, RecordType::Cname | RecordType::Any) {
        return names;
    }
    for _ in 0..MAX_CHAIN {
        let current = &names[names.len() - 1];
        let next = answers.iter().find_map(|r| match &r.data {
            RData::Cname(target) if r.name == *current => Some(target.clone()),
            _ => None,
        });
        match next {
            Some(target) if !names.contains(&target) => names.push(target),
            _ => break,
        }
    }
    names
}

/// The response for an authoritative lookup. Answers from our zones carry AA (referrals do not).
/// A CNAME chain ending in a missing name answers NXDOMAIN, one ending in a missing type NOERROR
/// (RFC 6604 section 3: the RCODE describes the last name in the chain).
pub(crate) fn authoritative(
    query: &Message,
    question: &Question,
    zones: &ZoneSet,
    result: LookupResult,
    dnssec_ok: bool,
) -> Message {
    let mut msg = Message::response_to(query);
    msg.header.aa = true;
    match result {
        LookupResult::Answer {
            answers,
            authority,
            additional,
        } => {
            if authority.iter().any(|r| r.rtype == RecordType::Soa) {
                let names = chain(&question.name, question.qtype, &answers);
                let last = Question {
                    name: names[names.len() - 1].clone(),
                    ..question.clone()
                };
                if names.len() > 1
                    && matches!(
                        zones.lookup(&last, dnssec_ok),
                        Some(LookupResult::NxDomain { .. })
                    )
                {
                    msg.header.rcode = Rcode::NxDomain;
                }
            }
            msg.answers = answers;
            msg.authority = authority;
            msg.additional = additional;
        }
        LookupResult::Referral {
            ns,
            ds_or_proof,
            glue,
        } => {
            msg.header.aa = false;
            msg.authority = ns;
            msg.authority.extend(ds_or_proof);
            msg.additional = glue;
        }
        LookupResult::NoData { authority } => msg.authority = authority,
        LookupResult::NxDomain { authority } => {
            msg.header.rcode = Rcode::NxDomain;
            msg.authority = authority;
        }
    }
    msg
}

fn is_dnssec_type(t: RecordType) -> bool {
    matches!(t, RecordType::Rrsig | RecordType::Nsec | RecordType::Nsec3)
}

/// Scrubs an upstream response before it is cached or served.
///
/// Returns `None` when the response does not answer exactly `question` (it must never be cached
/// or served). Otherwise keeps only what belongs to the question (bailiwick):
/// - answers: records of the CNAME chain starting at the question name (owner on the chain,
///   class of the question, type CNAME or the asked type; RRSIGs only for DO clients);
/// - authority: for negative answers the SOA of a zone enclosing the final chain name, plus,
///   for DO clients, NSEC/NSEC3/RRSIG proofs below that zone; for positive answers only DNSSEC
///   proofs for DO clients (minimal responses: no NS records);
/// - additional: nothing (minimal responses).
///
/// AA and AD are cleared: we are not authoritative for forwarded data and the answer has not
/// been validated.
pub(crate) fn scrub(question: &Question, mut resp: Message, dnssec_ok: bool) -> Option<Message> {
    if resp.questions.len() != 1 || resp.questions[0] != *question {
        return None;
    }
    resp.header.aa = false;
    resp.header.ad = false;
    resp.additional.clear();
    if !matches!(resp.header.rcode, Rcode::NoError | Rcode::NxDomain) {
        resp.answers.clear();
        resp.authority.clear();
        return Some(resp);
    }
    let names = chain(&question.name, question.qtype, &resp.answers);
    let class_ok = |r: &Record| r.class == question.qclass || question.qclass == Class::Any;
    resp.answers.retain(|r| {
        class_ok(r)
            && names.contains(&r.name)
            && (r.rtype == RecordType::Cname
                || r.rtype == question.qtype
                || question.qtype == RecordType::Any
                || (dnssec_ok && r.rtype == RecordType::Rrsig))
    });
    let last = &names[names.len() - 1];
    let positive = resp.answers.iter().any(|r| {
        r.name == *last && (r.rtype == question.qtype || question.qtype == RecordType::Any)
    });
    if positive {
        resp.authority
            .retain(|r| dnssec_ok && is_dnssec_type(r.rtype));
    } else {
        let zone = resp
            .authority
            .iter()
            .find(|r| r.rtype == RecordType::Soa && class_ok(r) && last.is_subdomain_of(&r.name))
            .map(|r| r.name.clone());
        resp.authority.retain(|r| match &zone {
            Some(z) if r.rtype == RecordType::Soa => r.name == *z,
            Some(z) => dnssec_ok && is_dnssec_type(r.rtype) && r.name.is_subdomain_of(z),
            None => false,
        });
    }
    Some(resp)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use dnsy_proto::Soa;

    use super::*;

    fn name(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn rec(owner: &str, data: RData) -> Record {
        Record {
            name: name(owner),
            rtype: data.rtype(),
            class: Class::In,
            ttl: 300,
            data,
        }
    }

    fn soa(owner: &str) -> Record {
        rec(
            owner,
            RData::Soa(Soa {
                mname: name("ns.example."),
                rname: name("h.example."),
                serial: 1,
                refresh: 1,
                retry: 1,
                expire: 1,
                minimum: 60,
            }),
        )
    }

    fn question(qname: &str, qtype: RecordType) -> Question {
        Question {
            name: name(qname),
            qtype,
            qclass: Class::In,
        }
    }

    fn response(q: &Question) -> Message {
        let mut query = Message::response_to(&Message::decode(&[0; 12]).unwrap());
        query.questions.push(q.clone());
        query
    }

    #[test]
    fn scrub_drops_out_of_bailiwick_records() {
        let q = question("www.example.com.", RecordType::A);
        let mut resp = response(&q);
        resp.header.aa = true;
        resp.header.ad = true;
        resp.answers = vec![
            rec("www.example.com.", RData::Cname(name("cdn.example.net."))),
            rec("cdn.example.net.", RData::A(Ipv4Addr::new(192, 0, 2, 1))),
            rec(
                "bank.example.org.",
                RData::A(Ipv4Addr::new(203, 0, 113, 66)),
            ),
            rec(
                "www.example.com.",
                RData::Aaaa("2001:db8::1".parse().unwrap()),
            ),
        ];
        resp.authority = vec![rec("example.org.", RData::Ns(name("evil.example.")))];
        resp.additional = vec![rec("evil.example.", RData::A(Ipv4Addr::new(6, 6, 6, 6)))];
        let out = scrub(&q, resp, false).unwrap();
        let owners: Vec<String> = out.answers.iter().map(|r| r.name.to_string()).collect();
        assert_eq!(owners, ["www.example.com.", "cdn.example.net."]);
        assert_eq!(out.authority.len() + out.additional.len(), 0);
        assert!(!out.header.aa && !out.header.ad);
    }

    #[test]
    fn scrub_rejects_question_mismatch() {
        let q = question("www.example.com.", RecordType::A);
        let other = response(&question("www.example.org.", RecordType::A));
        assert!(scrub(&q, other, false).is_none());
        let mut none = response(&q);
        none.questions.clear();
        assert!(scrub(&q, none, false).is_none());
        let case = response(&question("WWW.Example.COM.", RecordType::A));
        assert!(scrub(&q, case, false).is_some());
    }

    #[test]
    fn scrub_negative_keeps_enclosing_soa_only() {
        let q = question("nope.example.com.", RecordType::A);
        let mut resp = response(&q);
        resp.header.rcode = Rcode::NxDomain;
        resp.authority = vec![
            soa("example.org."),
            soa("example.com."),
            rec("nope.example.com.", RData::Ns(name("x."))),
        ];
        let out = scrub(&q, resp.clone(), false).unwrap();
        assert_eq!(out.authority, vec![soa("example.com.")]);
        resp.authority = vec![soa("other.test.")];
        assert_eq!(scrub(&q, resp, false).unwrap().authority.len(), 0);
    }

    #[test]
    fn scrub_error_rcode_strips_data() {
        let q = question("a.example.", RecordType::A);
        let mut resp = response(&q);
        resp.header.rcode = Rcode::ServFail;
        resp.answers = vec![rec("a.example.", RData::A(Ipv4Addr::LOCALHOST))];
        let out = scrub(&q, resp, false).unwrap();
        assert_eq!(out.answers.len(), 0);
        assert_eq!(out.header.rcode, Rcode::ServFail);
    }

    #[test]
    fn chain_stops_on_loop_and_for_cname_queries() {
        let answers = vec![
            rec("a.example.", RData::Cname(name("b.example."))),
            rec("b.example.", RData::Cname(name("a.example."))),
        ];
        assert_eq!(chain(&name("a.example."), RecordType::A, &answers).len(), 2);
        assert_eq!(
            chain(&name("a.example."), RecordType::Cname, &answers).len(),
            1
        );
    }

    #[test]
    fn response_ip_policy_matches_v4_and_mapped_v6() {
        let policy = ResponseIpPolicy::new(["10.0.0.0/8".parse().unwrap()]);
        let q = question("a.example.", RecordType::A);
        let mut msg = response(&q);
        assert!(!policy.blocks(&msg));
        msg.answers = vec![rec(
            "a.example.",
            RData::Aaaa("::ffff:10.1.2.3".parse().unwrap()),
        )];
        assert!(policy.blocks(&msg));
        msg.answers = vec![rec("a.example.", RData::A(Ipv4Addr::new(192, 0, 2, 1)))];
        assert!(!policy.blocks(&msg));
        assert!(!ResponseIpPolicy::default().blocks(&msg));
    }
}
