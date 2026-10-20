use super::*;
use crate::{Class, Header, Message, Name, Opcode, Question, Rcode, RecordType};

fn query() -> Message {
    Message {
        header: Header {
            id: 7,
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
        questions: vec![Question {
            name: Name::from_ascii("example.com").unwrap(),
            qtype: RecordType::A,
            qclass: Class::In,
        }],
        answers: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        edns: None,
    }
}

/// Appends a raw OPT record (root owner, type 41) to an encoded message and bumps ARCOUNT.
fn with_raw_opt(mut wire: Vec<u8>, class: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    wire.push(0);
    wire.extend_from_slice(&41u16.to_be_bytes());
    wire.extend_from_slice(&class.to_be_bytes());
    wire.extend_from_slice(&ttl.to_be_bytes());
    wire.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    wire.extend_from_slice(rdata);
    let count = u16::from_be_bytes([wire[10], wire[11]]) + 1;
    wire[10..12].copy_from_slice(&count.to_be_bytes());
    wire
}

#[test]
fn opt_roundtrip() {
    let mut m = query();
    m.edns = Some(Edns {
        udp_payload: 4096,
        ext_rcode: 0,
        version: 0,
        dnssec_ok: false,
        options: vec![
            EdnsOption::Padding(5),
            EdnsOption::ClientSubnet(vec![0, 1, 24, 0, 192, 0, 2]),
            EdnsOption::Cookie(vec![1, 2, 3, 4, 5, 6, 7, 8]),
            EdnsOption::ExtendedError {
                code: 15,
                text: "blocked".into(),
            },
            EdnsOption::Unknown {
                code: 65001,
                data: vec![9, 9],
            },
        ],
    });
    let wire = m.encode(4096).unwrap();
    assert_eq!(Message::decode(&wire).unwrap(), m);
    assert_eq!(Message::decode(&wire).unwrap().additional, vec![]);
}

#[test]
fn two_opt_is_formerr() {
    let wire = with_raw_opt(
        with_raw_opt(query().encode(512).unwrap(), 1232, 0, &[]),
        1232,
        0,
        &[],
    );
    assert_eq!(Message::decode(&wire), Err(crate::DecodeError::BadOpt));
    let formerr = Message::formerr_for(&wire).unwrap();
    assert_eq!(
        Message::decode(&formerr).unwrap().header.rcode,
        Rcode::FormErr
    );
}

#[test]
fn opt_with_non_root_owner_is_rejected() {
    let mut wire = query().encode(512).unwrap();
    wire.extend_from_slice(&[1, b'a', 0, 0, 41, 4, 0xD0, 0, 0, 0, 0, 0, 0, 0]);
    wire[10..12].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(Message::decode(&wire), Err(crate::DecodeError::BadOpt));
}

#[test]
fn malformed_option_is_rejected() {
    let base = query().encode(512).unwrap();
    // option claims 4 octets, has 1
    let wire = with_raw_opt(base.clone(), 1232, 0, &[0, 99, 0, 4, 1]);
    assert!(Message::decode(&wire).is_err());
    // EDE shorter than its 2-octet code
    let wire = with_raw_opt(base, 1232, 0, &[0, 15, 0, 1, 1]);
    assert!(Message::decode(&wire).is_err());
}

#[test]
fn badvers_on_version_1() {
    let q = with_raw_opt(query().encode(512).unwrap(), 1232, 1 << 16, &[]);
    let q = Message::decode(&q).unwrap();
    let edns = q.edns.as_ref().unwrap();
    assert_eq!(edns.version, 1);
    assert_ne!(edns.version, EDNS_VERSION);
    let r = Message::badvers_for(&q);
    let got = Message::decode(&r.encode(512).unwrap()).unwrap();
    assert_eq!(got.header.rcode, Rcode::BadVers);
    assert_eq!(got.edns.as_ref().unwrap().version, EDNS_VERSION);
    assert_eq!(got.edns.unwrap().ext_rcode, 1);
    assert_eq!(got.answers, vec![]);
}

#[test]
fn ext_rcode_combines() {
    // BADVERS = 16: low nibble 0 in the header, 1 in the OPT.
    let wire = with_raw_opt(query().encode(512).unwrap(), 1232, 1 << 24, &[]);
    assert_eq!(Message::decode(&wire).unwrap().header.rcode, Rcode::BadVers);
    // low nibble from the header, high bits from OPT: 0x123
    let mut wire = with_raw_opt(query().encode(512).unwrap(), 1232, 0x12 << 24, &[]);
    wire[3] |= 3;
    assert_eq!(
        Message::decode(&wire).unwrap().header.rcode,
        Rcode::Unknown(0x123)
    );
    // and back
    let mut m = query();
    m.header.rcode = Rcode::Unknown(0x123);
    m.edns = Some(Edns::default());
    let got = Message::decode(&m.encode(512).unwrap()).unwrap();
    assert_eq!(got.header.rcode, Rcode::Unknown(0x123));
    assert_eq!(got.edns.unwrap().ext_rcode, 0x12);
    // without OPT only the low four bits survive
    let mut m = query();
    m.header.rcode = Rcode::BadVers;
    assert_eq!(
        Message::decode(&m.encode(512).unwrap())
            .unwrap()
            .header
            .rcode,
        Rcode::NoError
    );
    // wider than 12 bits cannot be encoded
    m.header.rcode = Rcode::Unknown(0x1000);
    m.edns = Some(Edns::default());
    assert_eq!(m.encode(512), Err(EncodeError::BadRcode));
}

#[test]
fn do_bit_roundtrip() {
    for dnssec_ok in [false, true] {
        let mut m = query();
        m.edns = Some(Edns {
            dnssec_ok,
            ..Edns::default()
        });
        let wire = m.encode(512).unwrap();
        assert_eq!(
            Message::decode(&wire).unwrap().edns.unwrap().dnssec_ok,
            dnssec_ok
        );
    }
}

#[test]
fn padding_block_468() {
    let mut m = query();
    m.edns = Some(Edns::default());
    let mut pad = query();
    pad.edns = Some(Edns {
        options: vec![EdnsOption::Padding(0)],
        ..Edns::default()
    });
    assert!(pad.edns.as_ref().unwrap().has_padding());
    assert!(!m.edns.as_ref().unwrap().has_padding());
    for answers in 0..40u8 {
        m.answers = (0..answers)
            .map(|i| crate::Record {
                name: Name::from_ascii(&format!("host{i}.example.com")).unwrap(),
                rtype: RecordType::A,
                class: Class::In,
                ttl: 60,
                data: crate::RData::A([192, 0, 2, i].into()),
            })
            .collect();
        let wire = m.encode_padded(65535).unwrap();
        assert_eq!(wire.len() % PADDING_BLOCK, 0, "{answers} answers");
        let got = Message::decode(&wire).unwrap();
        assert_eq!(got.answers, m.answers);
    }
    // existing padding is replaced, not stacked
    m.answers.clear();
    m.edns
        .as_mut()
        .unwrap()
        .options
        .push(EdnsOption::Padding(100));
    assert_eq!(m.encode_padded(65535).unwrap().len(), PADDING_BLOCK);
    // no OPT: nothing to pad
    m.edns = None;
    assert_eq!(m.encode_padded(65535).unwrap(), m.encode(65535).unwrap());
    // a small limit caps the padding instead of overflowing it
    m.edns = Some(Edns::default());
    let plain = m.encode(65535).unwrap().len();
    assert_eq!(m.encode_padded(plain + 10).unwrap().len(), plain + 10);
    assert_eq!(m.encode_padded(plain + 2).unwrap().len(), plain);
}

#[test]
fn ede_roundtrip() {
    let mut m = query();
    m.header.qr = true;
    assert!(m.edns.is_none());
    m.set_ede(ede::BLOCKED, "blocked by list");
    m.set_ede(ede::STALE_ANSWER, "");
    assert_eq!(m.edns.as_ref().unwrap().udp_payload, DEFAULT_UDP_PAYLOAD);
    let got = Message::decode(&m.encode(512).unwrap()).unwrap();
    assert_eq!(
        got.edns.unwrap().options,
        vec![
            EdnsOption::ExtendedError {
                code: 15,
                text: "blocked by list".into()
            },
            EdnsOption::ExtendedError {
                code: 3,
                text: String::new()
            },
        ]
    );
}
