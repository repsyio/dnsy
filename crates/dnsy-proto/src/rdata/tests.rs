use std::fmt::Write as _;

use super::*;

fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn sample() -> Vec<RData> {
    vec![
        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        RData::Aaaa("2001:db8::1".parse().unwrap()),
        RData::Ns(n("ns1.example.com.")),
        RData::Cname(n("www.example.com.")),
        RData::Ptr(n("host.example.com.")),
        RData::Mx {
            preference: 10,
            exchange: n("mail.example.com."),
        },
        RData::Txt(vec![
            b"v=spf1 -all".to_vec(),
            b"say \"hi\" \\ \x01".to_vec(),
        ]),
        RData::Soa(Soa {
            mname: n("ns1.example.com."),
            rname: n("hostmaster.example.com."),
            serial: 2_026_102_001,
            refresh: 7200,
            retry: 3600,
            expire: 1_209_600,
            minimum: 300,
        }),
        RData::Srv {
            priority: 1,
            weight: 5,
            port: 5060,
            target: n("sip.example.com."),
        },
        RData::Caa {
            flags: 0,
            tag: "issue".into(),
            value: b"letsencrypt.org".to_vec(),
        },
        RData::Opaque {
            rtype: 65280,
            data: vec![0xde, 0xad, 0xbe, 0xef],
        },
    ]
}

fn wire(d: &RData) -> Vec<u8> {
    let mut w = WireWriter::new();
    d.encode(&mut w).unwrap();
    w.finish()
}

fn decode(rtype: RecordType, buf: &[u8]) -> Result<RData, WireError> {
    RData::decode(rtype, &mut WireReader::new(buf), buf.len())
}

#[test]
fn rdata_roundtrip_each_type() {
    for d in sample() {
        let buf = wire(&d);
        assert_eq!(decode(d.rtype(), &buf).unwrap(), d, "wire {d}");
        assert_eq!(
            RData::parse(d.rtype(), &d.to_string()).unwrap(),
            d,
            "text {d}"
        );
    }
}

#[test]
fn txt_long_string_split() {
    let long = vec![b'x'; 600];
    let buf = wire(&RData::Txt(vec![long.clone()]));
    assert_eq!(buf.len(), 600 + 3);
    assert_eq!(buf[0], 255);
    assert_eq!(buf[256], 255);
    assert_eq!(buf[512], 90);
    let RData::Txt(parts) = decode(RecordType::Txt, &buf).unwrap() else {
        panic!("not txt")
    };
    assert_eq!(
        parts.iter().map(Vec::len).collect::<Vec<_>>(),
        [255, 255, 90]
    );
    assert_eq!(parts.concat(), long);
}

#[test]
fn txt_empty_strings_survive() {
    assert_eq!(wire(&RData::Txt(vec![])), [0]);
    let d = RData::Txt(vec![vec![], b"a".to_vec(), vec![]]);
    assert_eq!(decode(RecordType::Txt, &wire(&d)).unwrap(), d);
    assert_eq!(RData::parse(RecordType::Txt, r#""" "a" """#).unwrap(), d);
}

#[test]
fn unknown_type_rfc3597() {
    let t = RecordType::from(65280);
    let d = RData::parse(t, "\\# 4 DEADBEEF").unwrap();
    assert_eq!(
        d,
        RData::Opaque {
            rtype: 65280,
            data: vec![0xde, 0xad, 0xbe, 0xef]
        }
    );
    assert_eq!(d.to_string(), "\\# 4 DEADBEEF");
    assert_eq!(d.rtype(), t);
    assert_eq!(RData::parse(t, "\\# 0").unwrap().to_string(), "\\# 0");
    assert_eq!(RData::parse(t, "\\# 4 DEAD BEEF").unwrap(), d);
    assert_eq!(
        decode(t, &[1, 2, 3]).unwrap(),
        RData::Opaque {
            rtype: 65280,
            data: vec![1, 2, 3]
        }
    );
    // Known types accept the generic form too.
    assert_eq!(
        RData::parse(RecordType::A, "\\# 4 C0000201").unwrap(),
        RData::A(Ipv4Addr::new(192, 0, 2, 1))
    );
    // Without \# an unknown type has no presentation form.
    assert!(RData::parse(t, "DEADBEEF").is_err());
    assert!(RData::parse(RecordType::Opt, "x").is_err());
}

#[test]
fn presentation_matches_fixtures() {
    let mut out = String::new();
    for d in sample() {
        writeln!(out, "{:?} {d}", d.rtype()).unwrap();
    }
    insta::assert_snapshot!(out);
}

#[test]
fn name_compression_only_for_rfc1035_types() {
    let mut w = WireWriter::new();
    w.write_name(&n("example.com."));
    let base = w.len();
    RData::Ns(n("ns.example.com.")).encode(&mut w).unwrap();
    let ns_len = w.len() - base;
    RData::Srv {
        priority: 0,
        weight: 0,
        port: 1,
        target: n("ns.example.com."),
    }
    .encode(&mut w)
    .unwrap();
    let srv_len = w.len() - base - ns_len;
    assert_eq!(ns_len, 1 + 2 + 2);
    assert_eq!(srv_len, 6 + 16);
}

#[test]
fn decode_follows_compression_pointers() {
    let mut w = WireWriter::new();
    w.write_name(&n("example.com."));
    let start = w.len();
    RData::Mx {
        preference: 5,
        exchange: n("mx.example.com."),
    }
    .encode(&mut w)
    .unwrap();
    let buf = w.finish();
    let mut r = WireReader::new(&buf);
    r.read_name().unwrap();
    let d = RData::decode(RecordType::Mx, &mut r, buf.len() - start).unwrap();
    assert_eq!(
        d,
        RData::Mx {
            preference: 5,
            exchange: n("mx.example.com.")
        }
    );
}

#[test]
fn decode_rejects_malformed() {
    assert_eq!(decode(RecordType::A, &[1, 2, 3]), Err(WireError::Truncated));
    assert_eq!(
        decode(RecordType::A, &[1, 2, 3, 4, 5]),
        Err(WireError::BadRdata)
    );
    assert_eq!(
        decode(RecordType::Aaaa, &[0; 15]),
        Err(WireError::Truncated)
    );
    assert_eq!(decode(RecordType::Txt, &[]), Err(WireError::BadRdata));
    assert_eq!(
        decode(RecordType::Txt, &[5, b'a']),
        Err(WireError::Truncated)
    );
    assert_eq!(
        decode(RecordType::Caa, &[0, 9, b'a']),
        Err(WireError::Truncated)
    );
    assert_eq!(
        decode(RecordType::Caa, &[0, 1, 0xff]),
        Err(WireError::BadRdata)
    );
    assert_eq!(decode(RecordType::Ns, &[0, 0]), Err(WireError::BadRdata));
    assert_eq!(decode(RecordType::Mx, &[0]), Err(WireError::Truncated));
    // rdlen larger than the buffer
    let mut r = WireReader::new(&[1, 2]);
    assert_eq!(
        RData::decode(RecordType::A, &mut r, 4),
        Err(WireError::Truncated)
    );
    // rdlen shorter than the fields it contains
    let buf = [0, 10, 0];
    let mut r = WireReader::new(&buf);
    assert_eq!(
        RData::decode(RecordType::Mx, &mut r, 2),
        Err(WireError::BadRdata)
    );
}

#[test]
fn encode_rejects_oversized_caa_tag() {
    let d = RData::Caa {
        flags: 0,
        tag: "t".repeat(256),
        value: vec![],
    };
    assert_eq!(d.encode(&mut WireWriter::new()), Err(WireError::BadRdata));
}

#[test]
fn parse_rejects_bad_text() {
    use RdataParseError as E;
    let p = RData::parse;
    assert_eq!(p(RecordType::A, ""), Err(E::MissingField("address")));
    assert_eq!(p(RecordType::A, "1.2.3"), Err(E::InvalidField("address")));
    assert_eq!(p(RecordType::A, "1.2.3.4 5"), Err(E::TrailingData));
    assert_eq!(p(RecordType::Aaaa, "nope"), Err(E::InvalidField("address")));
    assert_eq!(
        p(RecordType::Mx, "x mail."),
        Err(E::InvalidField("preference"))
    );
    assert_eq!(
        p(RecordType::Mx, "70000 mail."),
        Err(E::InvalidField("preference"))
    );
    assert_eq!(p(RecordType::Ns, "a..b."), Err(E::InvalidField("name")));
    assert_eq!(p(RecordType::Txt, ""), Err(E::MissingField("string")));
    assert_eq!(p(RecordType::Txt, "\"open"), Err(E::UnterminatedQuote));
    assert_eq!(p(RecordType::Txt, "a\\"), Err(E::BadEscape));
    assert_eq!(p(RecordType::Txt, "\\999"), Err(E::BadEscape));
    assert_eq!(p(RecordType::Txt, "\\1a2"), Err(E::BadEscape));
    assert_eq!(
        p(RecordType::Txt, "é"),
        Err(E::InvalidField("non-ASCII character"))
    );
    assert_eq!(
        p(RecordType::Caa, "0 is-sue \"x\""),
        Err(E::InvalidField("tag"))
    );
    assert_eq!(p(RecordType::Caa, "0 issue"), Err(E::MissingField("value")));
    assert_eq!(
        p(RecordType::A, "\\# 3 C0000201"),
        Err(E::InvalidField("length"))
    );
    assert_eq!(
        p(RecordType::A, "\\# 4 C00002"),
        Err(E::InvalidField("length"))
    );
    assert_eq!(
        p(RecordType::A, "\\# 4 ZZ000201"),
        Err(E::InvalidField("hex"))
    );
    assert_eq!(
        p(RecordType::A, "\\# 3 C00002"),
        Err(E::InvalidField("rdata"))
    );
    assert_eq!(p(RecordType::A, "\\# 3"), Err(E::InvalidField("length")));
    assert_eq!(p(RecordType::A, "\\# 1 C"), Err(E::InvalidField("hex")));
    assert_eq!(p(RecordType::Ns, "\\# x"), Err(E::InvalidField("length")));
    assert_eq!(
        p(RecordType::Txt, "\"\\ff\""),
        Ok(RData::Txt(vec![b"ff".to_vec()]))
    );
    for e in [
        E::MissingField("x"),
        E::InvalidField("x"),
        E::BadEscape,
        E::UnterminatedQuote,
    ] {
        assert!(e.to_string().len() > 5);
    }
}

#[test]
fn txt_escapes_roundtrip() {
    let d = RData::parse(RecordType::Txt, r#""a\"b" c\032d \065"#).unwrap();
    assert_eq!(
        d,
        RData::Txt(vec![b"a\"b".to_vec(), b"c d".to_vec(), b"A".to_vec()])
    );
    let shown = RData::Txt(vec![vec![0, 0x7f, b'\\']]).to_string();
    assert_eq!(shown, r#""\000\127\\""#);
}
