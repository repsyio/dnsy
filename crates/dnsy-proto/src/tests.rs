use super::*;

fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

#[test]
fn name_rejects_long_label() {
    let label = "a".repeat(64);
    assert_eq!(
        Name::from_ascii(&format!("{label}.com")),
        Err(NameError::LabelTooLong)
    );
    assert!(Name::from_ascii(&format!("{}.com", "a".repeat(63))).is_ok());
}

#[test]
fn name_rejects_over_255() {
    let label = "a".repeat(63);
    // 3 * 64 + 1 = 193 octets fits, 4 * 64 + 1 = 257 does not.
    assert!(Name::from_ascii(&format!("{label}.{label}.{label}.")).is_ok());
    assert_eq!(
        Name::from_ascii(&format!("{label}.{label}.{label}.{label}.")),
        Err(NameError::NameTooLong)
    );
    // Exactly 255 octets: 3 * 64 + 62 = 254 label octets + root.
    let last = "b".repeat(61);
    assert_eq!(
        Name::from_ascii(&format!("{label}.{label}.{label}.{last}."))
            .unwrap()
            .wire_len(),
        255
    );
}

#[test]
fn name_eq_is_case_insensitive() {
    use std::collections::HashSet;
    assert_eq!(n("WwW.Example.COM"), n("www.example.com."));
    let set: HashSet<Name> = [n("A.b")].into_iter().collect();
    assert!(set.contains(&n("a.B")));
    assert_ne!(n("a.b"), n("a.c"));
}

#[test]
fn name_canonical_order_rfc4034() {
    let expected = [
        "example",
        "a.example",
        "yljkjljk.a.example",
        "Z.a.example",
        "zABC.a.EXAMPLE",
        "z.example",
        "\\001.z.example",
        "*.z.example",
        "\\200.z.example",
    ];
    let names: Vec<Name> = expected.iter().map(|s| n(s)).collect();
    for rotate in 0..names.len() {
        let mut shuffled = names.clone();
        shuffled.rotate_left(rotate);
        shuffled.reverse();
        shuffled.sort();
        assert_eq!(shuffled, names);
    }
    assert!(Name::root() < n("example"));
}

#[test]
fn name_presentation_escapes() {
    let name = n("a\\.b.c\\032d.\\\\.");
    assert_eq!(name.labels().next().unwrap(), b"a.b");
    assert_eq!(name.labels().nth(1).unwrap(), b"c d");
    assert_eq!(name.to_string(), "a\\.b.c\\032d.\\\\.");
    assert_eq!(Name::root().to_string(), ".");
    assert_eq!(n("Example.COM").to_string(), "Example.COM.");
    for bad in [
        "", "a..b", ".a", "a\\", "a\\25", "a\\256", "a\\2x5", "é.com",
    ] {
        assert!(Name::from_ascii(bad).is_err(), "{bad}");
    }
}

#[test]
fn name_tree_operations() {
    let name = n("www.Example.com");
    assert_eq!(name.label_count(), 3);
    assert_eq!(name.parent().unwrap(), n("example.com"));
    assert_eq!(Name::root().parent(), None);
    assert!(Name::root().is_root() && !name.is_root());
    assert!(name.is_subdomain_of(&n("EXAMPLE.com")));
    assert!(name.is_subdomain_of(&name));
    assert!(name.is_subdomain_of(&Name::root()));
    assert!(!n("example.com").is_subdomain_of(&name));
    assert!(!name.is_subdomain_of(&n("other.com")));
    assert_eq!(
        name.to_lowercase().as_wire(),
        n("www.example.com").as_wire()
    );
    assert_eq!(format!("{name:?}"), "Name(www.Example.com.)");
    assert_eq!(
        Name::from_labels([b"".as_slice()]),
        Err(NameError::EmptyLabel)
    );
}

#[test]
fn enums_roundtrip_u16() {
    for v in 0..=u16::MAX {
        assert_eq!(u16::from(RecordType::from(v)), v);
        assert_eq!(u16::from(Class::from(v)), v);
        assert_eq!(u16::from(Rcode::from(v)), v);
    }
    for v in 0..=u8::MAX {
        assert_eq!(u8::from(Opcode::from(v)), v);
    }
    assert_eq!(RecordType::from(28), RecordType::Aaaa);
    assert_eq!(Class::from(1), Class::In);
    assert_eq!(Rcode::from(3), Rcode::NxDomain);
    assert_eq!(Opcode::from(4), Opcode::Notify);
}

#[test]
fn header_roundtrip_ad_cd() {
    let header = Header {
        id: 0xBEEF,
        qr: true,
        opcode: Opcode::Query,
        aa: false,
        tc: true,
        rd: true,
        ra: true,
        ad: true,
        cd: true,
        rcode: Rcode::NxDomain,
    };
    let counts = Counts {
        questions: 1,
        answers: 2,
        authority: 3,
        additional: 4,
    };
    let bytes = header.encode(counts);
    assert_eq!(bytes[2..4], [0b1000_0011, 0b1011_0011]);
    assert_eq!(Header::decode(&bytes).unwrap(), (header, counts));
    let only_ad = Header {
        cd: false,
        ..header
    };
    assert!(Header::decode(&only_ad.encode(counts)).unwrap().0.ad);
    assert!(!Header::decode(&only_ad.encode(counts)).unwrap().0.cd);
    assert_eq!(Header::decode(&bytes[..11]), Err(WireError::Truncated));
}

#[test]
fn reader_detects_pointer_loop() {
    // Self pointer, and a forward pointer.
    assert_eq!(
        WireReader::new(&[0xC0, 0x00]).read_name(),
        Err(WireError::BadPointer)
    );
    assert_eq!(
        WireReader::new(&[0xC0, 0x02, 0, 0]).read_name(),
        Err(WireError::BadPointer)
    );
    // A -> B -> A through backwards-looking pointers is impossible; a pointer to a pointer chain works.
    let chain = [0, 0xC0, 0x00, 0xC0, 0x01];
    let mut r = WireReader::new(&chain);
    r.read_bytes(3).unwrap();
    assert_eq!(r.read_name().unwrap(), Name::root());
    assert_eq!(r.position(), 5);
}

#[test]
fn reader_hop_limit_and_errors() {
    // 130 chained pointers, each to the previous one, ending at the root.
    let mut buf = vec![0u8];
    for i in 0..130u16 {
        let target = if i == 0 { 0 } else { 1 + (i - 1) * 2 };
        buf.extend_from_slice(&(0xC000 | target).to_be_bytes());
    }
    let start = buf.len() - 2;
    let mut r = WireReader::new(&buf);
    r.read_bytes(start).unwrap();
    assert_eq!(r.read_name(), Err(WireError::BadPointer));
    assert_eq!(
        WireReader::new(&[0x40]).read_name(),
        Err(WireError::BadLabelType)
    );
    assert_eq!(
        WireReader::new(&[3, b'a']).read_name(),
        Err(WireError::Truncated)
    );
    assert_eq!(WireReader::new(&[]).read_name(), Err(WireError::Truncated));
    assert_eq!(
        WireReader::new(&[0xC0]).read_name(),
        Err(WireError::Truncated)
    );
    // Over-long name assembled from labels.
    let mut long = Vec::new();
    for _ in 0..5 {
        long.push(63);
        long.extend_from_slice(&[b'a'; 63]);
    }
    long.push(0);
    assert_eq!(
        WireReader::new(&long).read_name(),
        Err(WireError::BadName(NameError::NameTooLong))
    );
}

#[test]
fn reader_primitives() {
    let mut r = WireReader::new(&[1, 0, 2, 0, 0, 0, 3, 9]);
    assert_eq!(r.read_u8().unwrap(), 1);
    assert_eq!(r.read_u16().unwrap(), 2);
    assert_eq!(r.read_u32().unwrap(), 3);
    assert_eq!(r.remaining(), 1);
    assert_eq!(r.read_u16(), Err(WireError::Truncated));
    assert_eq!(r.read_bytes(usize::MAX), Err(WireError::Truncated));
}

#[test]
fn writer_compresses_shared_suffix() {
    let mut w = WireWriter::new();
    assert!(w.is_empty());
    w.write_name(&n("www.example.com"));
    let first = w.len();
    w.write_name(&n("MAIL.Example.com"));
    // "mail" label (5 octets) plus a 2-octet pointer.
    assert_eq!(w.len() - first, 7);
    w.write_name(&n("example.com"));
    w.write_name(&Name::root());
    let buf = w.finish();
    let mut r = WireReader::new(&buf);
    assert_eq!(r.read_name().unwrap(), n("www.example.com"));
    assert_eq!(r.read_name().unwrap(), n("mail.example.com"));
    assert_eq!(r.read_name().unwrap(), n("example.com"));
    assert_eq!(r.read_name().unwrap(), Name::root());
    assert_eq!(r.remaining(), 0);
}

#[test]
fn writer_never_points_past_0x4000() {
    let mut w = WireWriter::new();
    w.write_bytes(&vec![0u8; 0x4000]);
    w.write_name(&n("late.example"));
    let before = w.len();
    w.write_name(&n("late.example"));
    // Not registered, so written in full again.
    assert_eq!(w.len() - before, n("late.example").wire_len());
    w.write_u8(1);
    w.write_u16(0);
    w.write_u32(0);
    w.patch_u16(0, 0xABCD);
    assert_eq!(w.finish()[..2], [0xAB, 0xCD]);
}

#[test]
fn name_storage_crosses_the_inline_boundary() {
    // 31, 32 and 33 octets straddle the inline capacity; 255 is the maximum.
    for total in [2usize, 31, 32, 33, 100, 255] {
        let mut labels = Vec::new();
        let mut used = 1;
        while used + 1 < total {
            let len = (total - used - 1).min(40);
            labels.push(
                "aB".repeat(len / 2)
                    .into_bytes()
                    .into_iter()
                    .chain(vec![b'c'; len % 2])
                    .collect::<Vec<u8>>(),
            );
            used += len + 1;
        }
        let name = Name::from_labels(&labels).unwrap();
        assert_eq!(name.wire_len(), used);
        let lower = name.to_lowercase();
        assert_eq!(name, lower);
        assert_eq!(lower.as_wire(), name.as_wire().to_ascii_lowercase());
        let mut w = WireWriter::new();
        w.write_name(&name);
        let bytes = w.finish();
        assert_eq!(WireReader::new(&bytes).read_name().unwrap(), name);
        assert_eq!(name.clone().as_wire(), name.as_wire());
        if let Some(parent) = name.parent() {
            assert_eq!(
                parent.as_wire(),
                &name.as_wire()[usize::from(name.as_wire()[0]) + 1..]
            );
        }
    }
}

#[test]
fn reader_name_limits_match_from_labels() {
    // A 255 octet name read from the wire is accepted, one more octet is not.
    let label = [b'a'; 63];
    let mut ok = Vec::new();
    for _ in 0..3 {
        ok.push(63);
        ok.extend_from_slice(&label);
    }
    ok.push(61);
    ok.extend_from_slice(&[b'b'; 61]);
    ok.push(0);
    assert_eq!(ok.len(), 255);
    assert_eq!(WireReader::new(&ok).read_name().unwrap().wire_len(), 255);
    let mut too_long = ok.clone();
    too_long[3 * 64] = 62;
    too_long.insert(3 * 64 + 1, b'b');
    assert_eq!(
        WireReader::new(&too_long).read_name(),
        Err(NameError::NameTooLong.into())
    );
}

#[test]
fn writer_compresses_through_pointer_chains_case_insensitively() {
    let mut w = WireWriter::new();
    w.write_name(&n("www.example.com"));
    w.write_name(&n("mail.EXAMPLE.com")); // mail + pointer to example.com
    w.write_name(&n("ftp.Mail.example.COM")); // ftp + pointer to "mail" (itself ending in a pointer)
    w.write_name(&n("WWW.example.com"));
    let buf = w.finish();
    assert_eq!(buf.len(), 17 + 7 + 6 + 2);
    assert_eq!(buf[buf.len() - 2..], [0xC0, 0x00]);
    assert_eq!(buf[24..30], [3, b'f', b't', b'p', 0xC0, 17]);
    let mut r = WireReader::new(&buf);
    assert_eq!(r.read_name().unwrap(), n("www.example.com"));
    assert_eq!(r.read_name().unwrap(), n("mail.example.com"));
    assert_eq!(r.read_name().unwrap(), n("ftp.mail.example.com"));
    assert_eq!(r.read_name().unwrap(), n("www.example.com"));
}

#[test]
fn writer_probing_is_bounded_when_every_suffix_collides() {
    // A zero mask gives every suffix the same hash, the worst case a crafted set of colliding
    // names could produce. Each lookup may then compare at most MAX_PROBES entries.
    let mut w = WireWriter::new();
    w.hash_mask = 0;
    let names: Vec<Name> = (0..1500)
        .map(|i| n(&format!("host{i}.zone{}.example.com", i % 7)))
        .collect();
    let mut lookups = 0;
    for name in &names {
        lookups += usize::from(name.label_count());
        w.write_name(name);
    }
    assert!(w.probes <= lookups * 8, "{} probes", w.probes);
    let buf = w.finish();
    let mut r = WireReader::new(&buf);
    for name in &names {
        assert_eq!(&r.read_name().unwrap(), name);
    }
    assert_eq!(r.remaining(), 0);
}

#[test]
fn writer_output_does_not_depend_on_the_hash_seed() {
    // The per-process hash key only picks table slots; the compression layout is fixed.
    let mut w = WireWriter::new();
    for name in ["a.example.com", "B.EXAMPLE.COM", "x.b.example.com"] {
        w.write_name(&n(name));
    }
    let mut want = b"\x01a\x07example\x03com\x00".to_vec();
    want.extend_from_slice(&[1, b'B', 0xC0, 2]);
    want.extend_from_slice(&[1, b'x', 0xC0, 15]);
    assert_eq!(w.finish(), want);
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
}

#[test]
fn prop_name_wire_roundtrip() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..2000 {
        let mut writer = WireWriter::new();
        let mut names = Vec::new();
        for _ in 0..=rng.below(4) {
            let labels: Vec<Vec<u8>> = (0..rng.below(5))
                .map(|_| {
                    // Small alphabet so suffixes collide and compression kicks in.
                    (0..=rng.below(6))
                        .map(|_| b"aAbB.\\\x00\xff"[rng.below(8)])
                        .collect()
                })
                .collect();
            let name = Name::from_labels(&labels).unwrap();
            writer.write_name(&name);
            names.push(name);
        }
        let buf = writer.finish();
        let mut reader = WireReader::new(&buf);
        for name in &names {
            let read = reader.read_name().unwrap();
            assert_eq!(&read, name);
            assert_eq!(
                Name::from_ascii(&read.to_string()).unwrap().as_wire(),
                read.as_wire()
            );
        }
        assert_eq!(reader.remaining(), 0);
    }
}

#[test]
fn error_display() {
    assert_eq!(
        WireError::BadName(NameError::NonAscii).to_string(),
        "bad name: non-ASCII character"
    );
    for e in [
        NameError::EmptyLabel,
        NameError::LabelTooLong,
        NameError::NameTooLong,
        NameError::BadEscape,
    ] {
        assert_ne!(e.to_string(), "");
    }
    for e in [
        WireError::Truncated,
        WireError::BadPointer,
        WireError::BadLabelType,
    ] {
        assert_ne!(e.to_string(), "");
    }
}
