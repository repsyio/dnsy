//! Shared helpers: load RFC vector files from `tests/vectors/`.

use dnsy_proto::{Class, Dnskey, Ds, Name, RData, Record, RecordType, Rrsig};
use std::path::Path;

pub fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

/// Non-comment lines of a vector file.
pub fn lines(file: &str) -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(file);
    std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with(';'))
        .map(str::to_owned)
        .collect()
}

/// The base64 private seeds recorded as `; seed ...` comment lines.
pub fn seeds(file: &str) -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(file);
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter_map(|l| l.strip_prefix("; seed ").map(str::to_owned))
        .collect()
}

/// Parses `owner ttl IN TYPE rdata...`.
pub fn record(line: &str) -> Record {
    let mut it = line.splitn(5, ' ');
    let owner = n(it.next().unwrap());
    let ttl: u32 = it.next().unwrap().parse().unwrap();
    assert_eq!(it.next(), Some("IN"));
    let rtype = match it.next().unwrap() {
        "A" => RecordType::A,
        "MX" => RecordType::Mx,
        "DS" => RecordType::Ds,
        "DNSKEY" => RecordType::Dnskey,
        "RRSIG" => RecordType::Rrsig,
        other => panic!("unexpected type {other}"),
    };
    Record {
        name: owner,
        rtype,
        class: Class::In,
        ttl,
        data: RData::parse(rtype, it.next().unwrap()).unwrap(),
    }
}

pub fn dnskey(r: &Record) -> Dnskey {
    match &r.data {
        RData::Dnskey(k) => k.clone(),
        other => panic!("not a DNSKEY: {other:?}"),
    }
}

pub fn rrsig(r: &Record) -> Rrsig {
    match &r.data {
        RData::Rrsig(s) => s.clone(),
        other => panic!("not an RRSIG: {other:?}"),
    }
}

pub fn ds(r: &Record) -> Ds {
    match &r.data {
        RData::Ds(d) => d.clone(),
        other => panic!("not a DS: {other:?}"),
    }
}

/// One example: DNSKEY record, optional DS, the `RRset` record and its RRSIG.
pub struct Example {
    pub dnskey_record: Record,
    pub rrset: Vec<Record>,
    pub rrsig: Rrsig,
    pub ds: Option<Ds>,
}

impl Example {
    pub fn key(&self) -> Dnskey {
        dnskey(&self.dnskey_record)
    }
}

/// Groups vector lines: each example starts at a DNSKEY line and ends at its RRSIG.
pub fn examples(file: &str) -> Vec<Example> {
    let mut out = Vec::new();
    let mut cur: Option<Example> = None;
    for l in lines(file) {
        let r = record(&l);
        match r.rtype {
            RecordType::Dnskey => {
                cur = Some(Example {
                    dnskey_record: r,
                    rrset: Vec::new(),
                    rrsig: Rrsig {
                        type_covered: RecordType::A,
                        algorithm: 0,
                        labels: 0,
                        original_ttl: 0,
                        expiration: 0,
                        inception: 0,
                        key_tag: 0,
                        signer: n("."),
                        signature: Vec::new(),
                    },
                    ds: None,
                });
            }
            RecordType::Ds => cur.as_mut().unwrap().ds = Some(ds(&r)),
            RecordType::Rrsig => {
                let mut e = cur.take().unwrap();
                e.rrsig = rrsig(&r);
                out.push(e);
            }
            _ => cur.as_mut().unwrap().rrset.push(r),
        }
    }
    out
}
