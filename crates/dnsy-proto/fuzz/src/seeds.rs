//! Seed corpus: messages built with the encoder (every record type with a dedicated parser,
//! EDNS options, truncation) plus raw byte shapes the decoder has to survive.

use dnsy_proto::{
    Class, Edns, EdnsOption, Header, Message, Name, Opcode, Question, RData, Rcode, Record,
    RecordType, Soa,
};

fn n(s: &str) -> Name {
    Name::from_ascii(s).expect("valid name")
}

fn rec(name: &str, data: RData) -> Record {
    Record {
        name: n(name),
        rtype: data.rtype(),
        class: Class::In,
        ttl: 300,
        data,
    }
}

fn base(qtype: RecordType) -> Message {
    Message {
        header: Header {
            id: 0x1234,
            qr: true,
            opcode: Opcode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: true,
            ad: false,
            cd: false,
            rcode: Rcode::NoError,
        },
        questions: vec![Question {
            name: n("www.example.com"),
            qtype,
            qclass: Class::In,
        }],
        answers: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        edns: None,
    }
}

fn opaque(rtype: u16, data: &[u8]) -> RData {
    RData::Opaque {
        rtype,
        data: data.to_vec(),
    }
}

/// Encoder-built seeds.
pub fn messages() -> Vec<Vec<u8>> {
    let mut all = Vec::new();
    let mut push = |m: &Message| {
        if let Ok(w) = m.encode(usize::from(u16::MAX)) {
            all.push(w);
        }
    };

    let mut m = base(RecordType::Any);
    m.answers = vec![
        rec("www.example.com", RData::A([192, 0, 2, 1].into())),
        rec(
            "www.example.com",
            RData::Aaaa("2001:db8::1".parse().unwrap()),
        ),
        rec(
            "www.example.com",
            RData::Mx {
                preference: 10,
                exchange: n("Mail.Example.com"),
            },
        ),
        rec("www.example.com", RData::Cname(n("alias.example.com"))),
        rec("www.example.com", RData::Ns(n("ns1.example.com"))),
        rec("www.example.com", RData::Ptr(n("ptr.example.com"))),
        rec(
            "www.example.com",
            RData::Srv {
                priority: 1,
                weight: 2,
                port: 443,
                target: n("srv.example.com"),
            },
        ),
        rec(
            "www.example.com",
            opaque(39, n("Target.Example.COM").as_wire()),
        ),
        rec(
            "www.example.com",
            opaque(
                35,
                b"\0\x0a\0\x14\x01S\x03SIP\x00\x03Sip\x07example\x03com\x00",
            ),
        ),
        rec("www.example.com", opaque(65280, b"\x01\x02\x03")),
    ];
    m.authority = vec![rec(
        "example.com",
        RData::Soa(Soa {
            mname: n("ns1.example.com"),
            rname: n("hostmaster.example.com"),
            serial: 1,
            refresh: 7200,
            retry: 3600,
            expire: 1_209_600,
            minimum: 300,
        }),
    )];
    m.edns = Some(Edns::default());
    push(&m);

    // DNSSEC and text record shapes, built as raw RDATA so the parsers see valid input.
    let mut m = base(RecordType::Any);
    m.answers = vec![
        rec("www.example.com", opaque(16, b"\x05hello\x03abc")),
        rec(
            "www.example.com",
            opaque(257, b"\x00\x05issueletsencrypt.org"),
        ),
        rec(
            "www.example.com",
            opaque(48, &[1, 1, 3, 13, 1, 2, 3, 4, 5, 6, 7, 8]),
        ),
        rec(
            "www.example.com",
            opaque(43, &[0xAB, 0xCD, 13, 2, 1, 2, 3, 4, 5, 6]),
        ),
        rec(
            "www.example.com",
            opaque(
                46,
                &[
                    0, 1, 13, 2, 0, 0, 1, 44, 0x65, 0, 0, 0, 0x64, 0, 0, 0, 0x42, 7, b'e', b'x',
                    b'a', b'm', b'p', b'l', b'e', 0, 9, 9, 9,
                ],
            ),
        ),
        rec(
            "www.example.com",
            opaque(47, b"\x04next\x03com\x00\x00\x02\x40\x01"),
        ),
        rec(
            "www.example.com",
            opaque(50, b"\x01\x00\x00\x0a\x04salt\x04hash\x00\x02\x40\x01"),
        ),
        rec("www.example.com", opaque(51, b"\x01\x00\x00\x0a\x04salt")),
    ];
    m.edns = Some(Edns {
        options: vec![
            EdnsOption::Padding(8),
            EdnsOption::Unknown {
                code: 65001,
                data: vec![1, 2, 3],
            },
        ],
        dnssec_ok: true,
        ..Edns::default()
    });
    push(&m);

    let mut m = base(RecordType::A);
    m.header.rcode = Rcode::NxDomain;
    m.edns = Some(Edns::default());
    m.set_ede(18, "filtered");
    push(&m);

    let mut q = base(RecordType::A);
    q.header.qr = false;
    q.edns = Some(Edns {
        options: vec![EdnsOption::Padding(0)],
        ..Edns::default()
    });
    push(&q);
    all
}

/// Raw shapes: header-only, count lies, pointer shapes.
pub fn raw() -> Vec<Vec<u8>> {
    let hdr = |qd: u16, an: u16| {
        let mut v = vec![0x12, 0x34, 0x01, 0x00];
        for c in [qd, an, 0, 0] {
            v.extend_from_slice(&c.to_be_bytes());
        }
        v
    };
    let q = b"\x07example\x03com\x00\x00\x01\x00\x01";
    vec![
        hdr(0, 0),
        hdr(65535, 0),
        [hdr(1, 0), q.to_vec()].concat(),
        [hdr(1, 0), b"\xC0\x0C\x00\x01\x00\x01".to_vec()].concat(),
        [
            hdr(1, 1),
            q.to_vec(),
            b"\xC0\x0C\x00\x05\x00\x01\x00\x00\x0e\x10\x00\x02\xC0\x0C".to_vec(),
        ]
        .concat(),
        vec![0; 11],
    ]
}

/// All seeds.
pub fn all() -> Vec<Vec<u8>> {
    let mut v = messages();
    v.extend(raw());
    v
}
