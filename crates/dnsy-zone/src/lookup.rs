//! Authoritative lookup: RFC 1034 4.3.2 with RFC 4592 wildcards.
//!
//! Unsigned behaviour only; the DO paths are added with online signing.

use std::collections::BTreeMap;
use std::iter;
use std::sync::atomic::Ordering;

use dnsy_proto::{Class, Name, Question, RData, Record, RecordType};

use crate::model::Zone;
use crate::store::ZoneSet;

/// Most CNAMEs followed for one query.
const MAX_CNAME_CHAIN: usize = 8;

/// The outcome of an authoritative lookup. Negative `authority` holds the zone SOA with
/// TTL = min(SOA TTL, SOA minimum) (RFC 2308).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupResult {
    /// Data (possibly after a CNAME chain). A chain that ends in a missing name or type carries
    /// the negative SOA in `authority`; one that ends at a zone cut carries the referral NS in
    /// `authority` and its glue in `additional`.
    Answer {
        answers: Vec<Record>,
        authority: Vec<Record>,
        additional: Vec<Record>,
    },
    /// The name lies at or below a delegation.
    Referral {
        ns: Vec<Record>,
        ds_or_proof: Vec<Record>,
        glue: Vec<Record>,
    },
    /// The name exists (possibly as an empty non-terminal) but has no data of the type.
    NoData { authority: Vec<Record> },
    /// The name does not exist and no wildcard covers it.
    NxDomain { authority: Vec<Record> },
}

/// Record sets of one owner name, in file order per type. Empty for an empty non-terminal.
type Node = BTreeMap<RecordType, Vec<Record>>;

/// Lookup index of one zone, built once per snapshot.
#[derive(Debug)]
pub(crate) struct ZoneIndex {
    origin: Name,
    /// Every owner name and every empty non-terminal between an owner and the origin.
    nodes: BTreeMap<Name, Node>,
    /// The SOA as sent in negative answers.
    negative_soa: Record,
}

/// Where the descent through the zone tree stopped.
enum Found<'a> {
    /// An existing or wildcard-synthesised node, with the owner name to answer with.
    Node(Name, &'a Node),
    /// A zone cut at this name.
    Cut(&'a Name),
    NxDomain,
}

fn record(name: Name, ttl: u32, data: RData) -> Record {
    Record {
        name,
        rtype: data.rtype(),
        class: Class::In,
        ttl,
        data,
    }
}

impl ZoneIndex {
    pub(crate) fn build(zone: &Zone) -> Self {
        let soa = RData::Soa(zone.soa.clone());
        let mut nodes: BTreeMap<Name, Node> = BTreeMap::new();
        let apex = record(zone.origin.clone(), zone.soa_ttl, soa.clone());
        nodes
            .entry(zone.origin.clone())
            .or_default()
            .insert(RecordType::Soa, vec![apex]);
        for r in &zone.records {
            let rec = record(r.name.clone(), r.ttl, r.rdata.clone());
            nodes
                .entry(r.name.clone())
                .or_default()
                .entry(rec.rtype)
                .or_default()
                .push(rec);
        }
        let owners: Vec<Name> = nodes.keys().cloned().collect();
        for owner in owners {
            let mut cur = owner.parent();
            while let Some(n) = cur.filter(|n| *n != zone.origin) {
                cur = n.parent();
                nodes.entry(n).or_default();
            }
        }
        let ttl = zone.soa_ttl.min(zone.soa.minimum);
        Self {
            origin: zone.origin.clone(),
            nodes,
            negative_soa: record(zone.origin.clone(), ttl, soa),
        }
    }

    /// Descends from the origin towards `name` (RFC 1034 4.3.2 step 3). `name` must be in the
    /// zone.
    fn find(&self, name: &Name, qtype: RecordType) -> Found<'_> {
        let depth = name.label_count() - self.origin.label_count();
        let mut path = Vec::with_capacity(usize::from(depth));
        let mut cur = name.clone();
        for _ in 0..depth {
            let parent = cur.parent().expect("below the origin");
            path.push(cur);
            cur = parent;
        }
        let mut encloser = &self.origin;
        for n in path.iter().rev() {
            let Some((owner, node)) = self.nodes.get_key_value(n) else {
                return self.wildcard(encloser, name);
            };
            // The parent side is authoritative for DS at the cut itself (RFC 4035 3.1.4.1).
            if node.contains_key(&RecordType::Ns) && !(n == name && qtype == RecordType::Ds) {
                return Found::Cut(owner);
            }
            encloser = owner;
        }
        let (owner, node) = self
            .nodes
            .get_key_value(name)
            .expect("every name on the path exists");
        Found::Node(owner.clone(), node)
    }

    /// RFC 4592: only the source of synthesis `*.<closest encloser>` may answer for a name
    /// that does not exist.
    fn wildcard(&self, closest_encloser: &Name, name: &Name) -> Found<'_> {
        let star: &[u8] = b"*";
        let source = Name::from_labels(iter::once(star).chain(closest_encloser.labels()));
        match source.ok().and_then(|s| self.nodes.get(&s)) {
            Some(node) => Found::Node(name.clone(), node),
            None => Found::NxDomain,
        }
    }

    /// The NS records at a cut plus the address records of in-zone name servers.
    fn referral(&self, cut: &Name, rotation: usize) -> (Vec<Record>, Vec<Record>) {
        let ns = rotated(&self.nodes[cut][&RecordType::Ns], cut, rotation);
        let glue = self.addresses(&ns, rotation);
        (ns, glue)
    }

    /// A and AAAA records in this zone for the names NS, MX and SRV records point at.
    fn addresses(&self, records: &[Record], rotation: usize) -> Vec<Record> {
        let mut targets: Vec<&Name> = Vec::new();
        for r in records {
            let (RData::Ns(target)
            | RData::Mx {
                exchange: target, ..
            }
            | RData::Srv { target, .. }) = &r.data
            else {
                continue;
            };
            if target.is_subdomain_of(&self.origin) && !targets.contains(&target) {
                targets.push(target);
            }
        }
        let mut out = Vec::new();
        for (owner, node) in targets
            .into_iter()
            .filter_map(|t| self.nodes.get_key_value(t))
        {
            for rtype in [RecordType::A, RecordType::Aaaa] {
                if let Some(rrset) = node.get(&rtype) {
                    out.extend(rotated(rrset, owner, rotation));
                }
            }
        }
        out
    }

    /// RFC 1034 4.3.2 steps 3 to 6 for `qname`, following CNAMEs while `in_zone` holds for
    /// their targets.
    fn resolve(
        &self,
        qname: &Name,
        qtype: RecordType,
        rotation: usize,
        in_zone: impl Fn(&Name) -> bool,
    ) -> LookupResult {
        let mut chain: Vec<Record> = Vec::new();
        let mut visited: Vec<Name> = Vec::new();
        let mut name = qname.clone();
        loop {
            let (owner, node) = match self.find(&name, qtype) {
                Found::Cut(cut) => {
                    let (ns, glue) = self.referral(cut, rotation);
                    if chain.is_empty() {
                        return LookupResult::Referral {
                            ns,
                            ds_or_proof: Vec::new(),
                            glue,
                        };
                    }
                    return LookupResult::Answer {
                        answers: chain,
                        authority: ns,
                        additional: glue,
                    };
                }
                Found::NxDomain if chain.is_empty() => {
                    return LookupResult::NxDomain {
                        authority: vec![self.negative_soa.clone()],
                    };
                }
                Found::NxDomain => return self.negative_after(chain),
                Found::Node(owner, node) => (owner, node),
            };
            if !matches!(qtype, RecordType::Cname | RecordType::Any)
                && let Some(cname) = node.get(&RecordType::Cname)
            {
                if chain.len() == MAX_CNAME_CHAIN {
                    return LookupResult::Answer {
                        answers: chain,
                        authority: Vec::new(),
                        additional: Vec::new(),
                    };
                }
                let rec = record(owner.clone(), cname[0].ttl, cname[0].data.clone());
                let RData::Cname(target) = &rec.data else {
                    unreachable!("a CNAME RRset holds CNAME data");
                };
                let target = target.clone();
                chain.push(rec);
                visited.push(owner);
                if !target.is_subdomain_of(&self.origin)
                    || !in_zone(&target)
                    || visited.contains(&target)
                {
                    return LookupResult::Answer {
                        answers: chain,
                        authority: Vec::new(),
                        additional: Vec::new(),
                    };
                }
                name = target;
                continue;
            }
            let mut answers = Vec::new();
            if qtype == RecordType::Any {
                for rrset in node.values() {
                    answers.extend(rotated(rrset, &owner, rotation));
                }
            } else if let Some(rrset) = node.get(&qtype) {
                answers = rotated(rrset, &owner, rotation);
            }
            if answers.is_empty() {
                if chain.is_empty() {
                    return LookupResult::NoData {
                        authority: vec![self.negative_soa.clone()],
                    };
                }
                return self.negative_after(chain);
            }
            let additional = self.addresses(&answers, rotation);
            chain.extend(answers);
            return LookupResult::Answer {
                answers: chain,
                authority: Vec::new(),
                additional,
            };
        }
    }

    /// A CNAME chain whose last target has no data: the chain plus the negative SOA.
    fn negative_after(&self, chain: Vec<Record>) -> LookupResult {
        LookupResult::Answer {
            answers: chain,
            authority: vec![self.negative_soa.clone()],
            additional: Vec::new(),
        }
    }
}

/// The record set rotated left by `rotation`, owned by `owner` (the query name for wildcard
/// synthesis).
fn rotated(rrset: &[Record], owner: &Name, rotation: usize) -> Vec<Record> {
    let k = rotation % rrset.len().max(1);
    rrset[k..]
        .iter()
        .chain(&rrset[..k])
        .map(|r| Record {
            name: owner.clone(),
            ..r.clone()
        })
        .collect()
}

impl ZoneSet {
    /// Answers `q` from the closest enclosing zone; `None` when no zone encloses the name or
    /// the class is not IN (or ANY). Every call rotates the order of each record set by one.
    /// `dnssec_ok` is ignored until online signing.
    pub fn lookup(&self, q: &Question, _dnssec_ok: bool) -> Option<LookupResult> {
        if !matches!(q.qclass, Class::In | Class::Any) {
            return None;
        }
        let origin = &self.find(&q.name)?.origin;
        let index = self.indexes.get(origin)?;
        let rotation = self.rotation.fetch_add(1, Ordering::Relaxed);
        let in_zone = |n: &Name| self.find(n).is_some_and(|z| z.origin == *origin);
        Some(index.resolve(&q.name, q.qtype, rotation, in_zone))
    }
}

#[cfg(test)]
#[path = "lookup_tests.rs"]
mod tests;
