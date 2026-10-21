use super::*;
use crate::{Class, RecordType, TypeBitmap};
use std::net::Ipv4Addr;

fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn sig(type_covered: RecordType, labels: u8, ttl: u32) -> Rrsig {
    Rrsig {
        type_covered,
        algorithm: 13,
        labels,
        original_ttl: ttl,
        expiration: 0x0000_0200,
        inception: 0x0000_0100,
        key_tag: 0x0042,
        signer: n("Example.COM."),
        signature: vec![0xFF; 8],
    }
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

fn a(name: &str, last: u8) -> Record {
    rec(name, 999, RData::A(Ipv4Addr::new(192, 0, 2, last)))
}

fn prefix(rtype: u8, labels: u8) -> Vec<u8> {
    let mut v = vec![
        0, rtype, 13, labels, 0, 0, 0x0E, 0x10, 0, 0, 2, 0, 0, 0, 1, 0, 0,
        0x42, // fixed fields
    ];
    v.extend(b"\x07example\x03com\x00");
    v
}

fn rr(owner: &[u8], rdata: &[u8]) -> Vec<u8> {
    let mut v = owner.to_vec();
    v.extend([
        0,
        1,
        0,
        1,
        0,
        0,
        0x0E,
        0x10,
        0,
        u8::try_from(rdata.len()).unwrap(),
    ]);
    v.extend(rdata);
    v
}

const WWW: &[u8] = b"\x03www\x07example\x03com\x00";

#[test]
fn canonical_ordering_rfc4034_6_3() {
    let rrsig = sig(RecordType::A, 3, 3600);
    let set = [
        a("WWW.example.com.", 9),
        a("www.example.com.", 1),
        a("www.example.com.", 5),
    ];
    let mut expected = prefix(1, 3);
    for last in [1, 5, 9] {
        expected.extend(rr(WWW, &[192, 0, 2, last]));
    }
    assert_eq!(rrset_signing_input(&rrsig, &set), expected);

    // Duplicates collapse, original TTL replaces the record TTL.
    let dup = [a("www.example.com.", 1), a("WWW.example.com.", 1)];
    let mut expected = prefix(1, 3);
    expected.extend(rr(WWW, &[192, 0, 2, 1]));
    assert_eq!(rrset_signing_input(&rrsig, &dup), expected);

    // Left-aligned octet comparison: a shorter RDATA that is a prefix sorts first, and
    // no length prefix takes part in the ordering.
    let opaque = |d: &[u8]| {
        rec(
            "www.example.com.",
            1,
            RData::Opaque {
                rtype: 1,
                data: d.to_vec(),
            },
        )
    };
    let set = [
        opaque(&[1, 0, 0]),
        opaque(&[0, 255]),
        opaque(&[1]),
        opaque(&[1, 0]),
    ];
    let out = rrset_signing_input(&rrsig, &set);
    let mut expected = prefix(1, 3);
    for d in [&[0u8, 255][..], &[1], &[1, 0], &[1, 0, 0]] {
        expected.extend(rr(WWW, d));
    }
    assert_eq!(out, expected);
}

#[test]
fn canonical_wildcard_owner_uses_rrsig_labels() {
    // Expanded from *.example.com: three labels, RRSIG labels = 2.
    let rrsig = sig(RecordType::A, 2, 3600);
    let out = rrset_signing_input(&rrsig, &[a("Foo.Example.COM.", 1)]);
    let mut expected = prefix(1, 2);
    expected.extend(rr(b"\x01*\x07example\x03com\x00", &[192, 0, 2, 1]));
    assert_eq!(out, expected);

    // The wildcard itself (labels excludes the "*") and a labels value that is too
    // large are used unchanged.
    let out = rrset_signing_input(&rrsig, &[a("*.example.com.", 1)]);
    assert_eq!(out, expected);
    let big = sig(RecordType::A, 9, 3600);
    let out = rrset_signing_input(&big, &[a("www.example.com.", 1)]);
    assert!(out.ends_with(&rr(WWW, &[192, 0, 2, 1])));
    // Root owner.
    let out = rrset_signing_input(&sig(RecordType::A, 0, 3600), &[a(".", 1)]);
    assert!(out.ends_with(&rr(b"\x00", &[192, 0, 2, 1])));
}

#[test]
fn canonical_lowercases_rdata_names() {
    assert_eq!(
        rdata_wire(&RData::Ns(n("NS1.Example.COM."))),
        b"\x03ns1\x07example\x03com\x00"
    );
    assert_eq!(
        rdata_wire(&RData::Mx {
            preference: 10,
            exchange: n("MAIL.Example.com.")
        }),
        b"\x00\x0a\x04mail\x07example\x03com\x00"
    );
    // No compression even when SOA names share a suffix.
    let soa = RData::Soa(crate::Soa {
        mname: n("NS.Example.com."),
        rname: n("Host.EXAMPLE.com."),
        serial: 1,
        refresh: 2,
        retry: 3,
        expire: 4,
        minimum: 5,
    });
    let mut expected = b"\x02ns\x07example\x03com\x00\x04host\x07example\x03com\x00".to_vec();
    for v in 1u32..=5 {
        expected.extend(v.to_be_bytes());
    }
    assert_eq!(rdata_wire(&soa), expected);
    assert_eq!(
        rdata_wire(&RData::Srv {
            priority: 1,
            weight: 2,
            port: 3,
            target: n("T.Example.")
        }),
        b"\x00\x01\x00\x02\x00\x03\x01t\x07example\x00"
    );
    assert_eq!(rdata_wire(&RData::Cname(n("A.B."))), b"\x01a\x01b\x00");
    assert_eq!(rdata_wire(&RData::Ptr(n("A."))), b"\x01a\x00");

    // RFC 6840 5.1: NSEC and RRSIG names keep their case.
    let nsec = RData::Nsec {
        next: n("Host.Example."),
        types: TypeBitmap::from_types(&[RecordType::A]),
    };
    assert_eq!(rdata_wire(&nsec), b"\x04Host\x07Example\x00\x00\x01\x40");
    // Other types are the plain encoding; an invalid CAA tag yields nothing.
    assert_eq!(
        rdata_wire(&RData::A(Ipv4Addr::new(1, 2, 3, 4))),
        [1, 2, 3, 4]
    );
    let bad = RData::Caa {
        flags: 0,
        tag: String::new(),
        value: vec![],
    };
    assert_eq!(rdata_wire(&bad), Vec::<u8>::new());

    // The signer name in the signed prefix is lowercased too (see prefix).
    let out = rrset_signing_input(&sig(RecordType::Ns, 3, 3600), &[]);
    assert_eq!(out, prefix(2, 3));
}

#[test]
fn canonical_lowercases_dname_rdata() {
    let dname = RData::Opaque {
        rtype: 39,
        data: n("Example.COM.").as_wire().to_vec(),
    };
    assert_eq!(rdata_wire(&dname), n("example.com.").as_wire());

    let mut naptr = vec![0, 10, 0, 20, 1, b'S', 3, b'S', b'I', b'P', 2, b'A', b'B'];
    naptr.extend_from_slice(n("Sip.Example.COM.").as_wire());
    let mut want = naptr.clone();
    want.truncate(13);
    want.extend_from_slice(n("sip.example.com.").as_wire());
    let naptr = RData::Opaque {
        rtype: 35,
        data: naptr,
    };
    assert_eq!(rdata_wire(&naptr), want);
}

#[test]
fn malformed_opaque_dname_and_naptr_are_left_alone() {
    for (rtype, data) in [
        (39, vec![3, b'A', b'B']),
        (39, vec![0xC0, 0x0C]),
        (39, vec![]),
        (35, vec![0, 1, 0, 2, 5]),
        (35, vec![0, 1, 0, 2, 0, 0, 0, 1, b'A']),
        (35, vec![0, 1, 0, 2]),
    ] {
        let r = RData::Opaque {
            rtype,
            data: data.clone(),
        };
        assert_eq!(rdata_wire(&r), data);
    }
}
