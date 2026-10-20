//! In-memory signed zones and a fake `DnssecFetcher` for validator tests.

use dnsy_dnssec::{
    Algorithm, DigestType, DnssecFetcher, FetchError, SigningKey, TrustAnchors, ValidationOutcome,
    Validator, ds_for, nsec3_hash,
};
use dnsy_proto::{
    Class, Header, Message, Name, Nsec3, Opcode, Question, RData, Rcode, Record, RecordType, Soa,
    TypeBitmap, base32hex_encode,
};
use std::collections::HashMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

/// The validation clock used by every test.
pub const NOW: u32 = 1_800_000_000;
pub const INCEPTION: u32 = NOW - 3_600;
pub const EXPIRATION: u32 = NOW + 7 * 86_400;

pub fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

pub fn rec(owner: &str, data: RData) -> Record {
    Record {
        name: n(owner),
        rtype: data.rtype(),
        class: Class::In,
        ttl: 300,
        data,
    }
}

pub fn a(owner: &str) -> Record {
    rec(owner, RData::A(Ipv4Addr::new(192, 0, 2, 1)))
}

pub fn types(t: &[RecordType]) -> TypeBitmap {
    TypeBitmap::from_types(t)
}

/// A signed zone: a KSK signing the DNSKEY `RRset` and a ZSK signing everything else.
pub struct Zone {
    pub apex: Name,
    pub ksk: SigningKey,
    pub zsk: SigningKey,
}

impl Zone {
    pub fn new(apex: &str) -> Zone {
        Zone {
            apex: n(apex),
            ksk: SigningKey::generate(Algorithm::EcdsaP256Sha256, true).unwrap(),
            zsk: SigningKey::generate(Algorithm::EcdsaP256Sha256, false).unwrap(),
        }
    }

    pub fn dnskey_rrset(&self) -> Vec<Record> {
        [&self.ksk, &self.zsk]
            .iter()
            .map(|k| Record {
                name: self.apex.clone(),
                rtype: RecordType::Dnskey,
                class: Class::In,
                ttl: 3_600,
                data: RData::Dnskey(k.dnskey()),
            })
            .collect()
    }

    /// The DS `RRset` the parent publishes for this zone (SHA-256 of the KSK).
    pub fn ds_rrset(&self) -> Vec<Record> {
        let ds = ds_for(&self.apex, &self.ksk.dnskey(), DigestType::Sha256).unwrap();
        vec![Record {
            name: self.apex.clone(),
            rtype: RecordType::Ds,
            class: Class::In,
            ttl: 3_600,
            data: RData::Ds(ds),
        }]
    }

    /// `rrset` followed by its RRSIG (KSK for DNSKEY, ZSK otherwise).
    pub fn sign(&self, rrset: Vec<Record>) -> Vec<Record> {
        let key = if rrset[0].rtype == RecordType::Dnskey {
            &self.ksk
        } else {
            &self.zsk
        };
        self.sign_window(rrset, key, INCEPTION, EXPIRATION)
    }

    pub fn sign_window(
        &self,
        mut rrset: Vec<Record>,
        key: &SigningKey,
        inception: u32,
        expiration: u32,
    ) -> Vec<Record> {
        let sig = key
            .sign_rrset(&rrset, &self.apex, inception, expiration)
            .unwrap();
        rrset.push(sig);
        rrset
    }

    pub fn soa(&self) -> Vec<Record> {
        self.sign(vec![Record {
            name: self.apex.clone(),
            rtype: RecordType::Soa,
            class: Class::In,
            ttl: 300,
            data: RData::Soa(Soa {
                mname: self.apex.clone(),
                rname: self.apex.clone(),
                serial: 1,
                refresh: 1,
                retry: 1,
                expire: 1,
                minimum: 300,
            }),
        }])
    }

    pub fn nsec(&self, owner: &str, next: &str, t: &[RecordType]) -> Vec<Record> {
        self.sign(vec![rec(
            owner,
            RData::Nsec {
                next: n(next),
                types: types(t),
            },
        )])
    }

    /// A full NSEC3 chain (empty salt) over `names`.
    pub fn nsec3_chain(
        &self,
        names: &[(&str, &[RecordType])],
        opt_out: bool,
        iterations: u16,
    ) -> Nsec3Chain {
        let mut entries: Vec<([u8; 20], TypeBitmap)> = names
            .iter()
            .map(|(name, t)| (nsec3_hash(&n(name), &[], iterations), types(t)))
            .collect();
        entries.sort_by_key(|e| e.0);
        let records = (0..entries.len())
            .map(|i| {
                let next = entries[(i + 1) % entries.len()].0;
                Record {
                    name: n(&format!(
                        "{}.{}",
                        base32hex_encode(&entries[i].0),
                        self.apex
                    )),
                    rtype: RecordType::Nsec3,
                    class: Class::In,
                    ttl: 300,
                    data: RData::Nsec3(Nsec3 {
                        hash_alg: 1,
                        flags: u8::from(opt_out),
                        iterations,
                        salt: Vec::new(),
                        next_hashed: next.to_vec(),
                        types: entries[i].1.clone(),
                    }),
                }
            })
            .collect();
        Nsec3Chain {
            iterations,
            hashes: entries.iter().map(|e| e.0).collect(),
            records,
        }
    }
}

pub struct Nsec3Chain {
    iterations: u16,
    hashes: Vec<[u8; 20]>,
    records: Vec<Record>,
}

impl Nsec3Chain {
    /// The index of the record matching or covering `name`.
    pub fn index(&self, name: &str) -> usize {
        let h = nsec3_hash(&n(name), &[], self.iterations);
        match self.hashes.binary_search(&h) {
            Ok(i) => i,
            Err(0) => self.hashes.len() - 1,
            Err(i) => i - 1,
        }
    }

    /// The signed records matching or covering each of `names`, deduplicated.
    pub fn proof(&self, zone: &Zone, names: &[&str]) -> Vec<Record> {
        let mut idx: Vec<usize> = names.iter().map(|x| self.index(x)).collect();
        idx.sort_unstable();
        idx.dedup();
        idx.into_iter()
            .flat_map(|i| zone.sign(vec![self.records[i].clone()]))
            .collect()
    }
}

pub fn msg(
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
            aa: false,
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
        edns: None,
    }
}

/// A fake network answering DS and DNSKEY queries from a map.
#[derive(Default)]
pub struct Net {
    map: HashMap<(Name, RecordType), Message>,
    fetches: AtomicUsize,
}

impl Net {
    pub fn serve(&mut self, m: Message) {
        let q = &m.questions[0];
        self.map.insert((q.name.clone(), q.qtype), m);
    }

    /// Serves the zone's signed DNSKEY `RRset`.
    pub fn zone(&mut self, z: &Zone) {
        let name = z.apex.to_string();
        self.serve(msg(
            &name,
            RecordType::Dnskey,
            Rcode::NoError,
            z.sign(z.dnskey_rrset()),
            vec![],
        ));
    }

    /// Serves a secure delegation: the child's DS signed by the parent and its DNSKEYs.
    pub fn delegate(&mut self, parent: &Zone, child: &Zone) {
        let name = child.apex.to_string();
        self.serve(msg(
            &name,
            RecordType::Ds,
            Rcode::NoError,
            parent.sign(child.ds_rrset()),
            vec![],
        ));
        self.zone(child);
    }

    pub fn fetches(&self) -> usize {
        self.fetches.load(Ordering::Relaxed)
    }
}

impl DnssecFetcher for Net {
    fn fetch(&self, q: Question) -> impl Future<Output = Result<Message, FetchError>> + Send {
        self.fetches.fetch_add(1, Ordering::Relaxed);
        let r = self
            .map
            .get(&(q.name.clone(), q.qtype))
            .cloned()
            .ok_or_else(|| FetchError(format!("no data for {} {:?}", q.name, q.qtype)));
        async move { r }
    }
}

/// Polls a future that never waits (the fake fetcher is always ready).
pub fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

/// Trust anchors holding the root zone's KSK DS.
pub fn anchors(root: &Zone) -> TrustAnchors {
    let mut ta = TrustAnchors::new();
    let ds = ds_for(&root.apex, &root.ksk.dnskey(), DigestType::Sha256).unwrap();
    ta.add_ds(Name::root(), ds);
    ta
}

pub fn run(v: &Validator, net: &Net, resp: &Message) -> ValidationOutcome {
    block_on(v.validate(net, &resp.questions[0], resp, NOW))
}

/// An unsigned SOA record for `apex`, as an insecure zone would send it.
pub fn unsigned_soa(apex: &str) -> Record {
    rec(
        apex,
        RData::Soa(Soa {
            mname: n(apex),
            rname: n(apex),
            serial: 1,
            refresh: 1,
            retry: 1,
            expire: 1,
            minimum: 300,
        }),
    )
}

/// Flips a bit in the signature of every RRSIG in `records`.
pub fn corrupt(records: &mut [Record]) {
    for r in records {
        if let RData::Rrsig(s) = &mut r.data {
            let last = s.signature.len() - 1;
            s.signature[last] ^= 1;
        }
    }
}
