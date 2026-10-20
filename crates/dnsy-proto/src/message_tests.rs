use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;
use crate::Opcode;

fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn header(id: u16) -> Header {
    Header {
        id,
        qr: true,
        opcode: Opcode::Query,
        aa: false,
        tc: false,
        rd: true,
        ra: true,
        ad: false,
        cd: false,
        rcode: Rcode::NoError,
    }
}

fn rec(name: &str, data: RData) -> Record {
    let rtype = match &data {
        RData::A(_) => RecordType::A,
        RData::Aaaa(_) => RecordType::Aaaa,
        RData::Ns(_) => RecordType::Ns,
        RData::Cname(_) => RecordType::Cname,
        RData::Ptr(_) => RecordType::Ptr,
        RData::Mx { .. } => RecordType::Mx,
        RData::Soa(_) => RecordType::Soa,
        RData::Srv { .. } => RecordType::Srv,
        RData::Opaque { rtype, .. } => RecordType::from(*rtype),
    };
    Record {
        name: n(name),
        rtype,
        class: Class::In,
        ttl: 300,
        data,
    }
}

fn opt(payload: u16) -> Record {
    Record {
        name: Name::root(),
        rtype: RecordType::Opt,
        class: Class::from(payload),
        ttl: 0,
        data: RData::Opaque {
            rtype: 41,
            data: Vec::new(),
        },
    }
}

fn message(id: u16) -> Message {
    Message {
        header: header(id),
        questions: vec![Question {
            name: n("example.com"),
            qtype: RecordType::A,
            qclass: Class::In,
        }],
        answers: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
    }
}

const QNAME: &[u8] = b"\x07example\x03com\x00";
const TTL: &[u8] = b"\x00\x00\x0e\x10";
const SOA_TAIL: &[u8] =
    b"\x78\x49\x6a\x01\x00\x00\x1c\x20\x00\x00\x0e\x10\x00\x12\x75\x00\x00\x00\x0e\x10";

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// Responses as captured from `dig` against an authoritative server, byte for byte.
fn fixtures() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "A with OPT",
            cat(&[
                b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01",
                QNAME,
                b"\x00\x01\x00\x01",
                b"\xc0\x0c\x00\x01\x00\x01",
                TTL,
                b"\x00\x04\x5d\xb8\xd7\x0e",
                b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00",
            ]),
        ),
        (
            "AAAA",
            cat(&[
                b"\xab\xcd\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00",
                QNAME,
                b"\x00\x1c\x00\x01",
                b"\xc0\x0c\x00\x1c\x00\x01",
                TTL,
                b"\x00\x10\x26\x06\x28\x00\x02\x20\x00\x01\x02\x48\x18\x93\x25\xc8\x19\x46",
            ]),
        ),
        (
            "MX",
            cat(&[
                b"\x00\x07\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00",
                QNAME,
                b"\x00\x0f\x00\x01",
                b"\xc0\x0c\x00\x0f\x00\x01",
                TTL,
                b"\x00\x09\x00\x0a\x04mail\xc0\x0c",
            ]),
        ),
        (
            "SOA",
            cat(&[
                b"\x00\x08\x85\x00\x00\x01\x00\x01\x00\x00\x00\x00",
                QNAME,
                b"\x00\x06\x00\x01",
                b"\xc0\x0c\x00\x06\x00\x01",
                TTL,
                b"\x00\x26\x02ns\xc0\x0c\x0ahostmaster\xc0\x0c",
                SOA_TAIL,
            ]),
        ),
        (
            "NXDOMAIN",
            cat(&[
                b"\x00\x09\x81\x83\x00\x01\x00\x00\x00\x01\x00\x00",
                b"\x02nx",
                QNAME,
                b"\x00\x01\x00\x01",
                b"\xc0\x0f\x00\x06\x00\x01\x00\x00\x03\x84",
                b"\x00\x26\x02ns\xc0\x0f\x0ahostmaster\xc0\x0f",
                SOA_TAIL,
            ]),
        ),
    ]
}

#[test]
fn roundtrip_known_packets() {
    for (label, wire) in fixtures() {
        let msg = Message::decode(&wire).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(msg.encode(usize::MAX).unwrap(), wire, "{label}");
    }
    let f = fixtures();
    let a = Message::decode(&f[0].1).unwrap();
    assert_eq!(a.header.id, 0x1234);
    assert_eq!(a.answers[0].data, RData::A(Ipv4Addr::new(93, 184, 215, 14)));
    assert_eq!(a.additional[0], opt(1232));
    let aaaa = Message::decode(&f[1].1).unwrap();
    assert_eq!(
        aaaa.answers[0].data,
        RData::Aaaa(
            "2606:2800:220:1:248:1893:25c8:1946"
                .parse::<Ipv6Addr>()
                .unwrap()
        )
    );
    let mx = Message::decode(&f[2].1).unwrap();
    assert_eq!(
        mx.answers[0].data,
        RData::Mx {
            preference: 10,
            exchange: n("mail.example.com")
        }
    );
    let nx = Message::decode(&f[4].1).unwrap();
    assert_eq!(nx.header.rcode, Rcode::NxDomain);
    let RData::Soa(soa) = &nx.authority[0].data else {
        panic!("SOA expected")
    };
    assert_eq!(soa.rname, n("hostmaster.example.com"));
    assert_eq!(soa.serial, 2_018_077_185);
    assert_eq!(soa.minimum, 3600);
}

#[test]
fn rdata_names_compressed_only_where_allowed() {
    let mut msg = message(1);
    msg.answers = vec![
        rec("example.com", RData::Ns(n("ns.example.com"))),
        rec("www.example.com", RData::Cname(n("example.com"))),
        rec("1.example.com", RData::Ptr(n("example.com"))),
        rec(
            "_sip._udp.example.com",
            RData::Srv {
                priority: 1,
                weight: 2,
                port: 5060,
                target: n("example.com"),
            },
        ),
    ];
    let wire = msg.encode(512).unwrap();
    // NS, CNAME and PTR RDATA point at the question name; SRV spells its target out.
    assert!(wire.ends_with(b"\x00\x01\x00\x02\x13\xc4\x07example\x03com\x00"));
    let target_ptrs = wire.windows(2).filter(|w| *w == b"\xc0\x0c").count();
    assert!(target_ptrs >= 4, "{target_ptrs}");
    assert_eq!(Message::decode(&wire).unwrap(), msg);
}

fn big_answer() -> Message {
    let mut msg = message(7);
    // Three RRsets of 20 A records each, interleaved to prove RRsets are kept whole even when
    // their members are not contiguous.
    for i in 0..20u8 {
        for owner in ["a.example.com", "b.example.com", "c.example.com"] {
            msg.answers
                .push(rec(owner, RData::A(Ipv4Addr::new(192, 0, 2, i))));
        }
    }
    msg.authority
        .push(rec("example.com", RData::Ns(n("ns1.example.com"))));
    msg.additional.push(rec(
        "ns1.example.com",
        RData::A(Ipv4Addr::new(192, 0, 2, 53)),
    ));
    msg.additional.push(opt(1232));
    msg
}

#[test]
fn truncation_sets_tc_and_fits() {
    let msg = big_answer();
    let full = msg.encode(usize::MAX).unwrap();
    assert!(full.len() > 512);
    assert!(!Message::decode(&full).unwrap().header.tc);

    for max in [512, 300, 100, 60] {
        let wire = msg.encode(max).unwrap();
        assert!(wire.len() <= max, "{max}: {}", wire.len());
        let got = Message::decode(&wire).unwrap();
        assert!(got.header.tc, "{max}");
        assert_eq!(got.questions, msg.questions);
        assert_eq!(got.additional.last(), Some(&opt(1232)), "OPT kept at {max}");
        assert!(got.authority.is_empty() && got.additional.len() == 1);
        // Interleaved RRsets mean only "all 60" or "none" are whole-RRset prefixes.
        assert!(got.answers.is_empty(), "{max}: {}", got.answers.len());
    }

    // Contiguous RRsets: the largest whole-RRset prefix is kept.
    let mut contiguous = big_answer();
    contiguous.answers.sort_by(|a, b| a.name.cmp(&b.name));
    let wire = contiguous.encode(512).unwrap();
    let got = Message::decode(&wire).unwrap();
    assert!(got.header.tc && wire.len() <= 512);
    assert_eq!(got.answers.len() % 20, 0);
    assert_ne!(got.answers.len(), 0);
    assert_eq!(got.answers[..], contiguous.answers[..got.answers.len()]);

    // Dropping only additional data does not set TC (RFC 2181 9).
    let mut no_glue = msg.clone();
    no_glue.answers.truncate(3);
    let small = no_glue.encode(usize::MAX).unwrap();
    let wire = no_glue.encode(small.len() - 1).unwrap();
    let got = Message::decode(&wire).unwrap();
    assert!(!got.header.tc);
    assert_eq!(got.additional, vec![opt(1232)]);
    assert_eq!(got.authority.len(), 1);

    // Header, question and OPT alone larger than the limit.
    assert_eq!(msg.encode(30), Err(EncodeError::DoesNotFit));
}

#[test]
fn encode_rejects_oversized_sections() {
    let mut msg = message(1);
    msg.answers.push(rec(
        "example.com",
        RData::Opaque {
            rtype: 16,
            data: vec![0; 65_536],
        },
    ));
    assert_eq!(msg.encode(usize::MAX), Err(EncodeError::RdataTooLong));
    let mut msg = message(1);
    msg.authority = vec![rec("a", RData::A(Ipv4Addr::LOCALHOST)); 65_536];
    assert_eq!(msg.encode(usize::MAX), Err(EncodeError::TooManyRecords));
    let mut msg = message(1);
    msg.questions = vec![msg.questions[0].clone(); 65_536];
    assert_eq!(msg.encode(usize::MAX), Err(EncodeError::TooManyRecords));
}

#[test]
fn formerr_echoes_id() {
    // A query whose answer count promises data that is not there.
    let mut query = cat(&[b"\xbe\xef\x01\x10\x00\x01\x00\x05\x00\x00\x00\x00", QNAME]);
    query.extend_from_slice(b"\x00\x1c\x00\x01");
    assert!(Message::decode(&query).is_err());
    let resp = Message::decode(&Message::formerr_for(&query).unwrap()).unwrap();
    assert_eq!(resp.header.id, 0xBEEF);
    assert!(resp.header.qr && resp.header.rd && resp.header.cd);
    assert!(!resp.header.tc && !resp.header.aa);
    assert_eq!(resp.header.rcode, Rcode::FormErr);
    assert_eq!(
        resp.questions,
        vec![Question {
            name: n("example.com"),
            qtype: RecordType::Aaaa,
            qclass: Class::In
        }]
    );
    assert!(resp.answers.is_empty() && resp.additional.is_empty());

    // Unparseable question: id still echoed, no question.
    let bad = b"\x00\x2a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01";
    let resp = Message::decode(&Message::formerr_for(bad).unwrap()).unwrap();
    assert_eq!(resp.header.id, 42);
    assert_eq!(resp.questions, []);

    // Header unreadable, or the packet is a response: drop.
    assert_eq!(Message::formerr_for(&query[..11]), None);
    query[2] |= 0x80;
    assert_eq!(Message::formerr_for(&query), None);
}

#[test]
fn response_to_copies_query_identity() {
    let mut query = message(99);
    query.header.qr = false;
    query.header.cd = true;
    query.header.rd = false;
    query.header.opcode = Opcode::Notify;
    query.additional.push(opt(4096));
    let resp = Message::response_to(&query);
    assert_eq!(resp.header.id, 99);
    assert!(resp.header.qr && resp.header.cd && !resp.header.rd && !resp.header.ra);
    assert_eq!(resp.header.opcode, Opcode::Notify);
    assert_eq!(resp.header.rcode, Rcode::NoError);
    assert_eq!(resp.questions, query.questions);
    assert!(resp.answers.is_empty() && resp.authority.is_empty() && resp.additional.is_empty());
}

fn long_name_wire() -> Vec<u8> {
    // Five 63-octet labels: 320 octets on the wire.
    let mut out = Vec::new();
    for _ in 0..5 {
        out.push(63);
        out.extend_from_slice(&[b'a'; 63]);
    }
    out.push(0);
    out
}

#[test]
#[expect(clippy::too_many_lines, reason = "one table of hostile cases")]
fn decode_rejects_hostile_inputs() {
    let hdr = |qd: u16, an: u16| {
        let mut h = vec![0x55, 0x66, 0x01, 0x00];
        for c in [qd, an, 0, 0] {
            h.extend_from_slice(&c.to_be_bytes());
        }
        h
    };
    let a_record = |rdlen: &[u8], rdata: &[u8]| {
        [
            hdr(1, 1),
            QNAME.to_vec(),
            b"\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01".to_vec(),
            TTL.to_vec(),
            rdlen.to_vec(),
            rdata.to_vec(),
        ]
        .concat()
    };
    let mut payload_max = hdr(0, 0);
    payload_max.resize(65_535, 0);
    let cases: Vec<(&str, Vec<u8>, DecodeError)> = vec![
        ("empty", Vec::new(), DecodeError::ShortHeader),
        ("short header", vec![0; 11], DecodeError::ShortHeader),
        (
            "self pointer",
            [hdr(1, 0), b"\xc0\x0c\x00\x01\x00\x01".to_vec()].concat(),
            DecodeError::Wire(WireError::BadPointer),
        ),
        (
            "forward pointer",
            [hdr(1, 0), b"\xc0\x0e\x00\x01\x00\x01".to_vec()].concat(),
            DecodeError::Wire(WireError::BadPointer),
        ),
        (
            "pointer loop",
            // A backwards pointer to its own label repeats it until the 255-octet limit trips.
            [hdr(1, 0), b"\x01a\xc0\x0c\x00\x01\x00\x01".to_vec()].concat(),
            DecodeError::Wire(WireError::BadName(crate::NameError::NameTooLong)),
        ),
        (
            "label over 63",
            [
                hdr(1, 0),
                vec![64],
                vec![b'a'; 64],
                b"\x00\x00\x01\x00\x01".to_vec(),
            ]
            .concat(),
            DecodeError::Wire(WireError::BadLabelType),
        ),
        (
            "name over 255",
            [hdr(1, 0), long_name_wire(), b"\x00\x01\x00\x01".to_vec()].concat(),
            DecodeError::Wire(WireError::BadName(crate::NameError::NameTooLong)),
        ),
        (
            "question count larger than data",
            [hdr(2, 0), QNAME.to_vec(), b"\x00\x01\x00\x01".to_vec()].concat(),
            DecodeError::Wire(WireError::Truncated),
        ),
        (
            "answer count larger than data",
            hdr(0, u16::MAX),
            DecodeError::Wire(WireError::Truncated),
        ),
        (
            "truncated RDATA",
            a_record(b"\x00\x04", b"\xc0\x00"),
            DecodeError::Wire(WireError::Truncated),
        ),
        (
            "A RDATA of 3 octets",
            a_record(b"\x00\x03", b"\xc0\x00\x02"),
            DecodeError::BadRdata,
        ),
        (
            "name runs past RDLENGTH",
            [
                hdr(1, 1),
                QNAME.to_vec(),
                b"\x00\x02\x00\x01\xc0\x0c\x00\x02\x00\x01".to_vec(),
                TTL.to_vec(),
                b"\x00\x01\xc0\x0c".to_vec(),
            ]
            .concat(),
            DecodeError::BadRdata,
        ),
        (
            "trailing data",
            a_record(b"\x00\x04", b"\xc0\x00\x02\x01\xff"),
            DecodeError::TrailingData,
        ),
        ("65535-byte payload", payload_max, DecodeError::TrailingData),
        (
            "65535 bytes of 0xff",
            vec![0xff; 65_535],
            DecodeError::Wire(WireError::BadPointer),
        ),
    ];
    for (label, buf, want) in cases {
        assert_eq!(Message::decode(&buf), Err(want), "{label}");
        let formerr = Message::formerr_for(&buf);
        let readable_query = buf.len() >= HEADER_LEN && buf[2] & 0x80 == 0;
        assert_eq!(formerr.is_some(), readable_query, "{label}");
        if let Some(resp) = formerr {
            let resp = Message::decode(&resp).unwrap();
            assert_eq!(
                resp.header.id,
                u16::from_be_bytes([buf[0], buf[1]]),
                "{label}"
            );
            assert_eq!(resp.header.rcode, Rcode::FormErr, "{label}");
        }
    }
}

#[test]
fn decode_survives_mutated_packets() {
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    for (_, wire) in fixtures() {
        for _ in 0..3000 {
            let mut buf = wire.clone();
            for _ in 0..=rng.below(4) {
                let i = rng.below(buf.len());
                buf[i] = u8::try_from(rng.below(256)).unwrap();
            }
            buf.truncate(buf.len() - rng.below(4));
            if let Ok(msg) = Message::decode(&buf) {
                // OPT moves to the end on encode, so compare shape rather than order.
                let again = Message::decode(&msg.encode(usize::MAX).unwrap()).unwrap();
                assert_eq!(again.questions, msg.questions);
                assert_eq!(again.answers, msg.answers);
                assert_eq!(again.additional.len(), msg.additional.len());
            }
            let _ = Message::formerr_for(&buf);
        }
    }
}

#[test]
fn error_display() {
    assert_eq!(
        DecodeError::ShortHeader.to_string(),
        "message shorter than the header"
    );
    assert_eq!(
        DecodeError::Wire(WireError::Truncated).to_string(),
        "message truncated"
    );
    assert_eq!(
        DecodeError::BadRdata.to_string(),
        "RDATA does not match RDLENGTH"
    );
    assert_eq!(
        DecodeError::TrailingData.to_string(),
        "trailing data after the last section"
    );
    assert_eq!(
        EncodeError::TooManyRecords.to_string(),
        "more than 65535 entries in a section"
    );
    assert_eq!(
        EncodeError::RdataTooLong.to_string(),
        "RDATA longer than 65535 octets"
    );
    assert_eq!(
        EncodeError::DoesNotFit.to_string(),
        "header, questions and OPT exceed the size limit"
    );
}

/// Small deterministic generator so `dnsy-proto` stays dependency free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }

    fn u16(&mut self) -> u16 {
        u16::try_from(self.next() & 0xFFFF).unwrap()
    }

    fn u32(&mut self) -> u32 {
        u32::try_from(self.next() & 0xFFFF_FFFF).unwrap()
    }

    fn name(&mut self) -> Name {
        let labels: Vec<Vec<u8>> = (0..self.below(4))
            .map(|_| {
                (0..=self.below(3))
                    .map(|_| b"aAb-"[self.below(4)])
                    .collect()
            })
            .collect();
        Name::from_labels(&labels).unwrap()
    }

    fn data(&mut self) -> RData {
        match self.below(9) {
            0 => RData::A(Ipv4Addr::from(self.u32())),
            1 => RData::Aaaa(Ipv6Addr::from(u128::from(self.next()) << 64)),
            2 => RData::Ns(self.name()),
            3 => RData::Cname(self.name()),
            4 => RData::Ptr(self.name()),
            5 => RData::Mx {
                preference: self.u16(),
                exchange: self.name(),
            },
            6 => RData::Soa(Soa {
                mname: self.name(),
                rname: self.name(),
                serial: self.u32(),
                refresh: self.u32(),
                retry: self.u32(),
                expire: self.u32(),
                minimum: self.u32(),
            }),
            7 => RData::Srv {
                priority: self.u16(),
                weight: self.u16(),
                port: self.u16(),
                target: self.name(),
            },
            _ => RData::Opaque {
                rtype: [16, 99, 257, 65_280][self.below(4)],
                data: (0..self.below(12))
                    .map(|i| u8::try_from(i).unwrap())
                    .collect(),
            },
        }
    }

    fn records(&mut self) -> Vec<Record> {
        (0..self.below(6))
            .map(|_| {
                let data = self.data();
                let mut r = rec("x", data);
                r.name = self.name();
                r.ttl = self.u32();
                r.class = [Class::In, Class::Ch, Class::Unknown(7)][self.below(3)];
                r
            })
            .collect()
    }
}

#[test]
fn prop_message_roundtrip() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..3000 {
        let flags = rng.u16() & !0x0040; // the Z bit is not modelled
        let mut wire_header = [0u8; HEADER_LEN];
        wire_header[..2].copy_from_slice(&rng.u16().to_be_bytes());
        wire_header[2..4].copy_from_slice(&flags.to_be_bytes());
        let (header, _) = Header::decode(&wire_header).unwrap();
        let mut msg = Message {
            header,
            questions: (0..rng.below(3))
                .map(|_| Question {
                    name: rng.name(),
                    qtype: RecordType::from(rng.u16()),
                    qclass: Class::from(rng.u16()),
                })
                .collect(),
            answers: rng.records(),
            authority: rng.records(),
            additional: rng.records(),
        };
        if rng.below(2) == 0 {
            msg.additional.push(opt(rng.u16()));
        }
        let wire = msg.encode(usize::MAX).unwrap();
        assert_eq!(Message::decode(&wire).unwrap(), msg);

        let max = HEADER_LEN + rng.below(wire.len());
        if let Ok(short) = msg.encode(max) {
            assert!(short.len() <= max);
            let got = Message::decode(&short).unwrap();
            assert_eq!(got.questions, msg.questions);
            assert!(msg.answers.starts_with(&got.answers));
            assert!(msg.authority.starts_with(&got.authority));
            let kept_opt = got.additional.iter().filter(|r| r.rtype == RecordType::Opt);
            let want_opt = msg.additional.iter().filter(|r| r.rtype == RecordType::Opt);
            assert!(kept_opt.eq(want_opt));
            if got.answers.len() < msg.answers.len() || got.authority.len() < msg.authority.len() {
                assert!(got.header.tc);
            }
        }
    }
}
