//! Fuzz target for the chain-of-trust validator. The input is a sequence of
//! `u16`-length-prefixed DNS messages: the first is the upstream response under validation,
//! the rest are what the fetcher serves for DS and DNSKEY queries (matched by query type, the
//! first one otherwise). The trust anchor is the DNSKEY that signs the seed corpus.

use std::future::Future;
use std::pin::pin;
use std::sync::OnceLock;
use std::task::{Context, Poll, Waker};

use dnsy_dnssec::{Algorithm, DnssecFetcher, FetchError, SigningKey, TrustAnchors, Validator};
use dnsy_proto::{
    Class, Edns, Header, Message, Name, Opcode, Question, RData, Rcode, Record, RecordType,
};

/// Validation time, inside the seeds' signature window.
pub const NOW: u32 = 1_000_000;

struct World {
    validator: Validator,
    seeds: Vec<Vec<u8>>,
}

fn n(s: &str) -> Name {
    Name::from_ascii(s).expect("valid name")
}

fn rec(name: &str, ttl: u32, data: RData) -> Record {
    Record {
        name: n(name),
        rtype: data.rtype(),
        class: Class::In,
        ttl,
        data,
    }
}

fn msg(
    qname: &str,
    qtype: RecordType,
    rcode: Rcode,
    answers: Vec<Record>,
    authority: Vec<Record>,
) -> Message {
    Message {
        header: Header {
            id: 1,
            qr: true,
            opcode: Opcode::Query,
            aa: true,
            tc: false,
            rd: true,
            ra: true,
            ad: false,
            cd: true,
            rcode,
        },
        questions: vec![Question {
            name: n(qname),
            qtype,
            qclass: Class::In,
        }],
        answers,
        authority,
        additional: Vec::new(),
        edns: Some(Edns {
            dnssec_ok: true,
            ..Edns::default()
        }),
    }
}

fn frame(parts: &[&Message]) -> Vec<u8> {
    let mut out = Vec::new();
    for m in parts {
        let w = m.encode(usize::from(u16::MAX)).expect("seed encodes");
        out.extend_from_slice(&u16::try_from(w.len()).expect("fits").to_be_bytes());
        out.extend_from_slice(&w);
    }
    out
}

fn world() -> &'static World {
    static WORLD: OnceLock<World> = OnceLock::new();
    WORLD.get_or_init(|| {
        let key = SigningKey::generate(Algorithm::EcdsaP256Sha256, true).expect("key");
        let root = n(".");
        let sign = |set: Vec<Record>| {
            let sig = key
                .sign_rrset(&set, &root, 1_000, 2_000_000_000)
                .expect("signs");
            let mut v = set;
            v.push(sig);
            v
        };
        let mut anchors = TrustAnchors::new();
        anchors.add_dnskey(root.clone(), key.dnskey());

        let dnskey = sign(vec![rec(".", 3600, RData::Dnskey(key.dnskey()))]);
        let keys = msg(".", RecordType::Dnskey, Rcode::NoError, dnskey, vec![]);

        let a = sign(vec![rec("www.", 300, RData::A([192, 0, 2, 1].into()))]);
        let positive = msg("www.", RecordType::A, Rcode::NoError, a, vec![]);

        let soa = sign(vec![rec(
            ".",
            300,
            RData::Soa(dnsy_proto::Soa {
                mname: n("ns."),
                rname: n("host."),
                serial: 1,
                refresh: 1,
                retry: 1,
                expire: 1,
                minimum: 300,
            }),
        )]);
        let types = dnsy_proto::TypeBitmap::from_types(&[
            RecordType::Soa,
            RecordType::Ns,
            RecordType::Rrsig,
            RecordType::Nsec,
            RecordType::Dnskey,
        ]);
        let nsec = sign(vec![rec(
            ".",
            300,
            RData::Nsec {
                next: n("a."),
                types,
            },
        )]);
        let nodata = msg(
            ".",
            RecordType::Txt,
            Rcode::NoError,
            vec![],
            [soa, nsec].concat(),
        );

        World {
            validator: Validator::new(anchors),
            seeds: vec![
                frame(&[&positive, &keys]),
                frame(&[&nodata, &keys]),
                frame(&[&positive, &nodata, &keys]),
            ],
        }
    })
}

/// Seeds for the mutation engine and for the committed corpus.
pub fn seeds() -> Vec<Vec<u8>> {
    world().seeds.clone()
}

struct Net(Vec<Message>);

impl DnssecFetcher for Net {
    fn fetch(&self, q: Question) -> impl Future<Output = Result<Message, FetchError>> + Send {
        let found = self
            .0
            .iter()
            .find(|m| m.questions.first().is_some_and(|x| x.qtype == q.qtype))
            .or(self.0.first())
            .cloned()
            .ok_or_else(|| FetchError("no data".into()));
        async move { found }
    }
}

fn split(data: &[u8]) -> Vec<Message> {
    let mut out = Vec::new();
    let mut rest = data;
    while let [a, b, tail @ ..] = rest {
        let len = usize::from(u16::from_be_bytes([*a, *b]));
        let (chunk, after) = tail.split_at(len.min(tail.len()));
        let Ok(m) = Message::decode(chunk) else { break };
        out.push(m);
        rest = after;
    }
    out
}

/// Validates the first message with the rest served by the fetcher. Must never panic.
pub fn validate_target(data: &[u8]) {
    let _ = validate(data);
}

/// The validator's verdict for `data`, `None` when the input does not frame into a response.
pub fn validate(data: &[u8]) -> Option<dnsy_core::DnssecStatus> {
    let mut messages = split(data);
    if messages.is_empty() {
        return None;
    }
    let resp = messages.remove(0);
    let q = resp.questions.first().cloned()?;
    let net = Net(messages);
    let mut fut = pin!(world().validator.validate(&net, &q, &resp, NOW));
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return Some(out.status);
        }
    }
}

#[cfg(test)]
mod tests {
    use dnsy_core::DnssecStatus;

    #[test]
    fn seeds_validate_as_secure() {
        for s in super::seeds() {
            assert_eq!(super::validate(&s), Some(DnssecStatus::Secure));
        }
    }
}
