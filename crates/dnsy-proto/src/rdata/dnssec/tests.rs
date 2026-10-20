use super::*;
use crate::RData;

fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn wire(d: &RData) -> Vec<u8> {
    let mut w = WireWriter::new();
    d.encode(&mut w).unwrap();
    w.finish()
}

fn decode(rtype: RecordType, buf: &[u8]) -> Result<RData, WireError> {
    RData::decode(rtype, &mut WireReader::new(buf), buf.len())
}

const RFC4034_KEY: &str = "AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==";

fn sample() -> Vec<RData> {
    let key = Dnskey {
        flags: 257,
        protocol: 3,
        algorithm: 13,
        public_key: (1..=64).collect(),
    };
    let ds = Ds {
        key_tag: 60485,
        algorithm: 5,
        digest_type: 1,
        digest: vec![0x2B, 0xB1, 0x83, 0xAF, 0x5F],
    };
    vec![
        RData::Dnskey(key.clone()),
        RData::Cdnskey(key),
        RData::Rrsig(Rrsig {
            type_covered: RecordType::Mx,
            algorithm: 13,
            labels: 2,
            original_ttl: 3600,
            expiration: 1_800_000_000,
            inception: 1_700_000_000,
            key_tag: 2642,
            signer: n("Example.COM."),
            signature: vec![1, 2, 3, 4, 5, 6, 7],
        }),
        RData::Ds(ds.clone()),
        RData::Cds(ds),
        RData::Nsec {
            next: n("host.example.com."),
            types: TypeBitmap::from_types(&[
                RecordType::A,
                RecordType::Mx,
                RecordType::Rrsig,
                RecordType::Nsec,
                RecordType::Unknown(1234),
            ]),
        },
        RData::Nsec {
            next: Name::root(),
            types: TypeBitmap::default(),
        },
        RData::Nsec3(Nsec3 {
            hash_alg: 1,
            flags: 1,
            iterations: 12,
            salt: vec![0xAA, 0xBB, 0xCC, 0xDD],
            next_hashed: (1..=20).collect(),
            types: TypeBitmap::from_types(&[RecordType::A, RecordType::Rrsig]),
        }),
        RData::Nsec3(Nsec3 {
            hash_alg: 1,
            flags: 0,
            iterations: 0,
            salt: vec![],
            next_hashed: vec![7],
            types: TypeBitmap::default(),
        }),
        RData::Nsec3param(Nsec3Param {
            hash_alg: 1,
            flags: 0,
            iterations: 12,
            salt: vec![0xAA, 0xBB, 0xCC, 0xDD],
        }),
        RData::Nsec3param(Nsec3Param {
            hash_alg: 1,
            flags: 0,
            iterations: 0,
            salt: vec![],
        }),
    ]
}

#[test]
fn dnssec_rdata_roundtrip_each_type() {
    for d in sample() {
        let buf = wire(&d);
        assert_eq!(decode(d.rtype(), &buf).unwrap(), d, "wire {d}");
        assert_eq!(
            RData::parse(d.rtype(), &d.to_string()).unwrap(),
            d,
            "text {d}"
        );
        assert_eq!(wire(&decode(d.rtype(), &buf).unwrap()), buf);
    }
}

#[test]
fn key_tag_matches_rfc4034_example() {
    let key = Dnskey {
        flags: 256,
        protocol: 3,
        algorithm: 5,
        public_key: parse_base64(RFC4034_KEY).unwrap(),
    };
    assert_eq!(key.key_tag(), 60485);
    assert!(key.is_zone_key());
    assert!(!key.is_sep());
    let sep = Dnskey { flags: 257, ..key };
    assert!(sep.is_sep());
}

#[test]
fn key_tag_algorithm_1_special_case() {
    let key = |public_key: Vec<u8>| Dnskey {
        flags: 256,
        protocol: 3,
        algorithm: 1,
        public_key,
    };
    assert_eq!(key(vec![9, 9, 0x12, 0x34, 0x56]).key_tag(), 0x1234);
    assert_eq!(key(vec![0x12, 0x34, 0x56]).key_tag(), 0x1234);
    assert_eq!(key(vec![1, 2]).key_tag(), 0);
    assert_eq!(key(vec![]).key_tag(), 0);
}

#[test]
fn key_tag_empty_and_huge_keys_do_not_panic() {
    let key = Dnskey {
        flags: 0xFFFF,
        protocol: 255,
        algorithm: 255,
        public_key: vec![0xFF; 65_000],
    };
    let _ = key.key_tag();
}

#[test]
fn rfc4034_ds_and_rrsig_presentation() {
    let ds = RData::parse(
        RecordType::Ds,
        "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118",
    )
    .unwrap();
    assert_eq!(
        ds.to_string(),
        "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118"
    );
    let sig = RData::parse(
        RecordType::Rrsig,
        "A 5 3 86400 20030322173103 20030220173103 2642 example.com. AQIDBAUG",
    )
    .unwrap();
    let RData::Rrsig(sig) = sig else { panic!() };
    assert_eq!(sig.type_covered, RecordType::A);
    assert_eq!(sig.expiration, parse_timestamp("20030322173103").unwrap());
    assert_eq!(sig.signature, [1, 2, 3, 4, 5, 6]);
    // Split base64 across tokens, as in zone files.
    let key = RData::parse(RecordType::Dnskey, "256 3 5 AQID BAUG").unwrap();
    assert_eq!(
        key,
        RData::Dnskey(Dnskey {
            flags: 256,
            protocol: 3,
            algorithm: 5,
            public_key: vec![1, 2, 3, 4, 5, 6]
        })
    );
}

#[test]
fn cds_cdnskey_delete_forms() {
    let cds = RData::parse(RecordType::Cds, "0 0 0 00").unwrap();
    assert_eq!(decode(RecordType::Cds, &wire(&cds)).unwrap(), cds);
    let cdnskey = RData::parse(RecordType::Cdnskey, "0 3 0 AA==").unwrap();
    assert_eq!(
        decode(RecordType::Cdnskey, &wire(&cdnskey)).unwrap(),
        cdnskey
    );
    assert_eq!(cds.rtype(), RecordType::Cds);
    assert_eq!(cdnskey.rtype(), RecordType::Cdnskey);
}

#[test]
fn type_bitmap_roundtrip() {
    // RFC 4034 4.3: A MX RRSIG NSEC TYPE1234.
    let bm = TypeBitmap::from_types(&[
        RecordType::Nsec,
        RecordType::A,
        RecordType::Unknown(1234),
        RecordType::Rrsig,
        RecordType::Mx,
        RecordType::A,
    ]);
    let mut expected = vec![0x00, 0x06, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03, 0x04, 0x1B];
    expected.extend([0u8; 26]);
    expected.push(0x20);
    let mut w = WireWriter::new();
    bm.encode(&mut w);
    let buf = w.finish();
    assert_eq!(buf, expected);
    let decoded = TypeBitmap::decode(&mut WireReader::new(&buf), buf.len()).unwrap();
    assert_eq!(decoded, bm);
    assert!(decoded.contains(RecordType::Mx));
    assert!(decoded.contains(RecordType::Unknown(1234)));
    assert!(!decoded.contains(RecordType::Txt));
    assert_eq!(bm.to_string(), " A MX RRSIG NSEC TYPE1234");
    assert!(!bm.is_empty());
    assert!(TypeBitmap::default().is_empty());

    // Highest type, and a full-width window.
    let top = TypeBitmap::from_types(&[RecordType::Unknown(0), RecordType::Unknown(65535)]);
    let mut w = WireWriter::new();
    top.encode(&mut w);
    let buf = w.finish();
    assert_eq!(
        TypeBitmap::decode(&mut WireReader::new(&buf), buf.len()).unwrap(),
        top
    );
}

#[test]
fn type_bitmap_rejects_malformed() {
    let bad: &[&[u8]] = &[
        &[0x00, 0x00],                         // empty window
        &[0x00, 0x21, 0x01],                   // oversized (33) and truncated
        &[0x00, 0x01],                         // truncated block
        &[0x00],                               // truncated header
        &[0x00, 0x01, 0x00],                   // all-zero block (trailing zero octet)
        &[0x00, 0x02, 0x40, 0x00],             // trailing zero octet
        &[0x01, 0x01, 0x40, 0x00, 0x01, 0x40], // windows out of order
        &[0x00, 0x01, 0x40, 0x00, 0x01, 0x40], // window repeated
    ];
    for buf in bad {
        assert!(
            TypeBitmap::decode(&mut WireReader::new(buf), buf.len()).is_err(),
            "{buf:02x?}"
        );
    }
    let mut oversized = vec![0x00, 33];
    oversized.extend([0xFF; 33]);
    assert!(TypeBitmap::decode(&mut WireReader::new(&oversized), oversized.len()).is_err());
    // A block that runs past the RDATA end even though the buffer continues.
    let buf = [0x00, 0x02, 0x40, 0x40];
    assert!(TypeBitmap::decode(&mut WireReader::new(&buf), 3).is_err());
}

#[test]
fn type_mnemonics() {
    assert_eq!(type_from_text("a").unwrap(), RecordType::A);
    assert_eq!(type_from_text("TYPE1").unwrap(), RecordType::A);
    assert_eq!(
        type_from_text("type65280").unwrap(),
        RecordType::Unknown(65280)
    );
    for bad in [
        "",
        "TYPE",
        "TYPE+1",
        "TYPE65536",
        "TYP",
        "FOO",
        "TYPE1x",
        "é",
    ] {
        assert!(type_from_text(bad).is_err(), "{bad}");
    }
    assert_eq!(type_name(RecordType::Unknown(65280)), "TYPE65280");
}

#[test]
fn rrsig_time_serial_arithmetic() {
    assert_eq!(format_timestamp(0), "19700101000000");
    assert_eq!(format_timestamp(u32::MAX), "21060207062815");
    assert_eq!(format_timestamp(1_700_000_000), "20231114221320");
    for t in [0, 1, 951_782_400, 1_709_251_199, 1_709_251_200, u32::MAX] {
        assert_eq!(parse_timestamp(&format_timestamp(t)), Some(t));
    }
    assert_eq!(parse_timestamp("1700000000"), Some(1_700_000_000));
    for bad in [
        "",
        "x",
        "20230231000000",
        "20231301000000",
        "20230101240000",
        "20230101006000",
        "20230101000060",
        "21060207062816",
        "19691231235959",
        "20230001000000",
        "20230100000000",
        "99999999999999",
        "4294967296",
        "-1",
    ] {
        assert_eq!(parse_timestamp(bad), None, "{bad}");
    }
    assert_eq!(parse_timestamp("20240229000000"), Some(1_709_164_800));

    assert!(serial_lt(1, 2));
    assert!(!serial_lt(2, 1));
    assert!(!serial_lt(5, 5));
    // Wrap-around: 0xFFFF_FFF0 is "before" 0x10.
    assert!(serial_lt(0xFFFF_FFF0, 0x10));
    assert!(serial_gt(0x10, 0xFFFF_FFF0));
    // Exactly 2^31 apart is undefined: neither.
    assert!(!serial_lt(0, 1 << 31) && !serial_gt(0, 1 << 31));

    let sig = |inception, expiration| Rrsig {
        type_covered: RecordType::A,
        algorithm: 13,
        labels: 2,
        original_ttl: 60,
        expiration,
        inception,
        key_tag: 1,
        signer: n("example.com."),
        signature: vec![0],
    };
    let s = sig(100, 200);
    assert!(s.is_current(100) && s.is_current(150) && s.is_current(200));
    assert!(!s.is_current(99) && !s.is_current(201));
    // A validity window that wraps the 32-bit counter.
    let wrap = sig(0xFFFF_FF00, 0x100);
    assert!(wrap.is_current(0xFFFF_FFFF) && wrap.is_current(0) && wrap.is_current(0x100));
    assert!(!wrap.is_current(0x101) && !wrap.is_current(0xFFFF_FE00));
}

#[test]
fn nsec3_presentation_base32hex() {
    // RFC 5155 Appendix A.
    let text = "1 1 12 aabbccdd 2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG";
    let RData::Nsec3(n3) = RData::parse(RecordType::Nsec3, text).unwrap() else {
        panic!()
    };
    assert_eq!(n3.next_hashed.len(), 20);
    assert_eq!(n3.salt, [0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(
        n3.to_string(),
        "1 1 12 AABBCCDD 2VPTU5TIMAMQTTGL4LUU9KG21E0AOR3S A RRSIG"
    );
    assert_eq!(
        RData::parse(RecordType::Nsec3param, "1 0 12 aabbccdd")
            .unwrap()
            .to_string(),
        "1 0 12 AABBCCDD"
    );
    assert_eq!(
        RData::parse(RecordType::Nsec3param, "1 0 0 -")
            .unwrap()
            .to_string(),
        "1 0 0 -"
    );

    // RFC 4648 section 10 vectors (base32hex, padding stripped).
    for (raw, enc) in [
        (&b""[..], ""),
        (b"f", "CO"),
        (b"fo", "CPNG"),
        (b"foo", "CPNMU"),
        (b"foob", "CPNMUOG"),
        (b"fooba", "CPNMUOJ1"),
        (b"foobar", "CPNMUOJ1E8"),
    ] {
        assert_eq!(base32hex_encode(raw), enc);
        if !raw.is_empty() {
            assert_eq!(base32hex_decode(enc).unwrap(), raw);
            assert_eq!(base32hex_decode(&enc.to_lowercase()).unwrap(), raw);
        }
    }
    for bad in ["", "C", "CPN", "CPNMUO", "CP", "CPNH", "!!", "CO=", "W0"] {
        assert!(base32hex_decode(bad).is_err(), "{bad}");
    }
}

#[test]
fn base64_vectors() {
    struct B(&'static [u8]);
    impl fmt::Display for B {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_base64(f, self.0)
        }
    }
    // RFC 4648 section 10.
    for (raw, enc) in [
        (&b"f"[..], "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg=="),
        (b"fooba", "Zm9vYmE="),
        (b"foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(B(raw).to_string(), enc);
        assert_eq!(parse_base64(enc).unwrap(), raw);
    }
    for bad in [
        "", "Zg", "Zg=", "Z===", "=Zg=", "Zm9v====", "Zg==Zm9v", "Zm$v", "Z g=",
    ] {
        assert!(parse_base64(bad).is_err(), "{bad}");
    }
}

#[test]
fn decode_rejects_unrepresentable_rdata() {
    // Empty key, signature, digest and next-hash have no presentation form.
    let cases: Vec<(RecordType, Vec<u8>)> = vec![
        (RecordType::Dnskey, vec![1, 0, 3, 13]),
        (RecordType::Cdnskey, vec![1, 0, 3, 13]),
        (RecordType::Ds, vec![0, 1, 13, 2]),
        (RecordType::Cds, vec![0, 1, 13, 2]),
        (
            RecordType::Rrsig,
            [
                &[0, 1, 13, 2, 0, 0, 0, 60, 0, 0, 0, 2, 0, 0, 0, 1, 0, 9][..],
                &[0],
            ]
            .concat(),
        ),
        (RecordType::Nsec3, vec![1, 0, 0, 0, 0, 0, 0]),
        (RecordType::Nsec, vec![0, 0, 0]),
        (RecordType::Nsec3param, vec![1, 0, 0, 0, 1]),
        (RecordType::Nsec3param, vec![1, 0, 0, 0, 0, 9]),
        (RecordType::Ds, vec![0, 1]),
        (RecordType::Dnskey, vec![]),
    ];
    for (rtype, buf) in cases {
        assert!(decode(rtype, &buf).is_err(), "{rtype:?} {buf:?}");
    }
}

#[test]
fn parse_rejects_bad_text() {
    let cases = [
        (RecordType::Dnskey, "256 3 5"),
        (RecordType::Dnskey, "256 3 5 !!!!"),
        (RecordType::Dnskey, "70000 3 5 AQID"),
        (RecordType::Ds, "1 5 1"),
        (RecordType::Ds, "1 5 1 XYZ"),
        (RecordType::Rrsig, "A 5 3 86400 20030322173103"),
        (
            RecordType::Rrsig,
            "A 5 3 86400 bad 20030220173103 2642 example.com. AQID",
        ),
        (
            RecordType::Rrsig,
            "NOPE 5 3 86400 1 1 2642 example.com. AQID",
        ),
        (RecordType::Nsec, ""),
        (RecordType::Nsec, "host.example.com. NOPE"),
        (RecordType::Nsec3, "1 0 0 - "),
        (RecordType::Nsec3, "1 0 0 - AB"),
        (
            RecordType::Nsec3,
            "1 0 0 zz 2VPTU5TIMAMQTTGL4LUU9KG21E0AOR3S",
        ),
        (RecordType::Nsec3param, "1 0 0"),
        (RecordType::Nsec3param, "1 0 0 - extra"),
    ];
    for (rtype, text) in cases {
        assert!(RData::parse(rtype, text).is_err(), "{rtype:?} {text}");
    }
    let long_salt = "AA".repeat(256);
    assert!(RData::parse(RecordType::Nsec3param, &format!("1 0 0 {long_salt}")).is_err());
}

#[test]
fn encode_rejects_oversized_nsec3_fields() {
    let mut n3 = Nsec3Param {
        hash_alg: 1,
        flags: 0,
        iterations: 0,
        salt: vec![0; 256],
    };
    assert!(n3.encode(&mut WireWriter::new()).is_err());
    n3.salt.clear();
    assert!(n3.encode(&mut WireWriter::new()).is_ok());
    let big = Nsec3 {
        hash_alg: 1,
        flags: 0,
        iterations: 0,
        salt: vec![],
        next_hashed: vec![],
        types: TypeBitmap::default(),
    };
    assert!(big.encode(&mut WireWriter::new()).is_err());
    let big = Nsec3 {
        next_hashed: vec![0; 256],
        ..big
    };
    assert!(big.encode(&mut WireWriter::new()).is_err());
}

#[test]
fn rrsig_decode_accepts_compressed_signer() {
    // Signer name written as a pointer back to an earlier name.
    let mut buf = vec![0u8; 0];
    buf.extend(b"\x07example\x03com\x00");
    let rdata_start = buf.len();
    buf.extend([
        0, 1, 13, 2, 0, 0, 0, 60, 0, 0, 0, 2, 0, 0, 0, 1, 0, 9, 0xC0, 0, 0xAB,
    ]);
    let mut r = WireReader::new(&buf);
    r.read_name().unwrap();
    let end = rdata_start + 21;
    let d = RData::decode(RecordType::Rrsig, &mut r, end - rdata_start).unwrap();
    let RData::Rrsig(s) = d else { panic!() };
    assert_eq!(s.signer, n("example.com."));
    assert_eq!(s.signature, [0xAB]);
}

/// Deterministic xorshift generator for the property tests.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn u16(&mut self) -> u16 {
        u16::try_from(self.next() >> 48).unwrap()
    }
    fn u32(&mut self) -> u32 {
        u32::try_from(self.next() >> 32).unwrap()
    }
    fn byte(&mut self) -> u8 {
        self.u16().to_le_bytes()[0]
    }
    fn bytes(&mut self, min: usize, max: usize) -> Vec<u8> {
        let len = min + (self.next() >> 8) as usize % (max - min + 1);
        (0..len).map(|_| self.byte()).collect()
    }
    fn name(&mut self) -> Name {
        let labels: Vec<Vec<u8>> = (0..self.next() % 4).map(|_| self.bytes(1, 12)).collect();
        Name::from_labels(labels).unwrap()
    }
    fn types(&mut self) -> TypeBitmap {
        let types: Vec<RecordType> = (0..self.next() % 8)
            .map(|_| RecordType::from(self.u16()))
            .collect();
        TypeBitmap::from_types(&types)
    }
}

#[test]
fn prop_dnssec_rdata_roundtrip() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..2000 {
        let key = Dnskey {
            flags: rng.u16(),
            protocol: rng.byte(),
            algorithm: rng.byte(),
            public_key: rng.bytes(1, 80),
        };
        let ds = Ds {
            key_tag: rng.u16(),
            algorithm: rng.byte(),
            digest_type: rng.byte(),
            digest: rng.bytes(1, 64),
        };
        let all = [
            RData::Dnskey(key.clone()),
            RData::Cdnskey(key),
            RData::Ds(ds.clone()),
            RData::Cds(ds),
            RData::Rrsig(Rrsig {
                type_covered: RecordType::from(rng.u16()),
                algorithm: rng.byte(),
                labels: rng.byte(),
                original_ttl: rng.u32(),
                expiration: rng.u32(),
                inception: rng.u32(),
                key_tag: rng.u16(),
                signer: rng.name(),
                signature: rng.bytes(1, 100),
            }),
            RData::Nsec {
                next: rng.name(),
                types: rng.types(),
            },
            RData::Nsec3(Nsec3 {
                hash_alg: rng.byte(),
                flags: rng.byte(),
                iterations: rng.u16(),
                salt: rng.bytes(0, 255),
                next_hashed: rng.bytes(1, 64),
                types: rng.types(),
            }),
            RData::Nsec3param(Nsec3Param {
                hash_alg: rng.byte(),
                flags: rng.byte(),
                iterations: rng.u16(),
                salt: rng.bytes(0, 255),
            }),
        ];
        for d in all {
            let buf = wire(&d);
            assert_eq!(decode(d.rtype(), &buf).unwrap(), d, "wire {d}");
            assert_eq!(
                RData::parse(d.rtype(), &d.to_string()).unwrap(),
                d,
                "text {d}"
            );
        }
    }
}

#[test]
fn prop_decoded_garbage_survives_presentation() {
    // Whatever the wire decoder accepts must have a presentation form that parses back.
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    let types = [
        RecordType::Dnskey,
        RecordType::Cdnskey,
        RecordType::Ds,
        RecordType::Cds,
        RecordType::Rrsig,
        RecordType::Nsec,
        RecordType::Nsec3,
        RecordType::Nsec3param,
    ];
    let mut accepted = 0;
    for i in 0..60_000 {
        let rtype = types[i % types.len()];
        let mut buf = rng.bytes(0, 48);
        // Bias towards plausible shapes so the decoders get past their headers.
        if i % 3 == 0 && rtype == RecordType::Nsec3 && buf.len() > 6 {
            buf[4] = 0;
            buf[5] = 1;
        }
        if let Ok(d) = decode(rtype, &buf) {
            accepted += 1;
            assert_eq!(RData::parse(rtype, &d.to_string()).unwrap(), d, "{d}");
            assert!(wire(&d).len() <= buf.len());
        }
    }
    assert!(accepted > 1000, "generator too weak: {accepted}");
}

#[test]
fn quote_in_name_label_survives_presentation() {
    let d = RData::Nsec {
        next: Name::from_labels([&b"\"a"[..], b"b"]).unwrap(),
        types: TypeBitmap::default(),
    };
    assert_eq!(RData::parse(RecordType::Nsec, &d.to_string()).unwrap(), d);
}
