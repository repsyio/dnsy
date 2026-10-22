//! Authenticated denial of existence: NSEC (RFC 4035 5.4, RFC 6840 4.4) and NSEC3
//! (RFC 5155 8, RFC 9276). Every record here has already been signature-verified against
//! the keys of `zone`.

use std::collections::HashMap;

use super::{Failure, Res, Verdict};
use crate::nsec3_hash;
use dnsy_proto::{Name, Nsec3, RData, Record, RecordType, TypeBitmap, base32hex_decode, ede};

const NSEC3_SHA1: u8 = 1;
const NSEC3_OPT_OUT: u8 = 0x01;
const DNAME: RecordType = RecordType::Unknown(39);

/// Memoised, budgeted NSEC3 hashing.
pub(super) struct Hasher {
    memo: HashMap<(Name, Vec<u8>, u16), [u8; 20]>,
    max: usize,
}

impl Hasher {
    pub(super) fn new(max: usize) -> Self {
        Self {
            memo: HashMap::new(),
            max,
        }
    }

    fn hash(&mut self, name: &Name, salt: &[u8], iterations: u16) -> Res<[u8; 20]> {
        let key = (name.to_lowercase(), salt.to_vec(), iterations);
        if let Some(h) = self.memo.get(&key) {
            return Ok(*h);
        }
        if self.memo.len() >= self.max {
            return Err(Failure::limit("NSEC3 hash computations"));
        }
        let h = nsec3_hash(name, salt, iterations);
        self.memo.insert(key, h);
        Ok(h)
    }
}

#[derive(Clone)]
struct NsecRec {
    owner: Name,
    next: Name,
    types: TypeBitmap,
    zone: Name,
}

impl NsecRec {
    /// `name` lies strictly between owner and next in canonical order (RFC 4034 6.1), and
    /// the record is not a delegation or DNAME record trying to deny names below it.
    fn covers(&self, name: &Name) -> bool {
        if !name.is_subdomain_of(&self.zone) {
            return false;
        }
        if name != &self.owner
            && name.is_subdomain_of(&self.owner)
            && (is_delegation(&self.types) || self.types.contains(DNAME))
        {
            return false;
        }
        if self.owner < self.next {
            &self.owner < name && name < &self.next
        } else {
            &self.owner < name || name < &self.next
        }
    }
}

#[derive(Clone)]
struct Nsec3Rec {
    hash: Vec<u8>,
    zone: Name,
    rec: Nsec3,
}

impl Nsec3Rec {
    fn hash_of(&self, name: &Name, h: &mut Hasher) -> Res<Option<[u8; 20]>> {
        if !name.is_subdomain_of(&self.zone) {
            return Ok(None);
        }
        h.hash(name, &self.rec.salt, self.rec.iterations).map(Some)
    }

    fn matches(&self, name: &Name, h: &mut Hasher) -> Res<bool> {
        Ok(self
            .hash_of(name, h)?
            .is_some_and(|x| x[..] == self.hash[..]))
    }

    fn covers(&self, name: &Name, h: &mut Hasher) -> Res<bool> {
        let Some(x) = self.hash_of(name, h)? else {
            return Ok(false);
        };
        let (owner, next, x) = (&self.hash[..], &self.rec.next_hashed[..], &x[..]);
        Ok(if owner < next {
            owner < x && x < next
        } else {
            owner < x || x < next
        })
    }

    fn opt_out(&self) -> bool {
        self.rec.flags & NSEC3_OPT_OUT != 0
    }
}

/// Validated NSEC and NSEC3 records from one response.
#[derive(Default)]
pub(super) struct Denial {
    nsec: Vec<NsecRec>,
    nsec3: Vec<Nsec3Rec>,
    max_iterations: u16,
}

/// What a DS denial proves about a name below a secure zone.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Cut {
    /// An unsigned delegation (or an opt-out span): the subtree is insecure.
    Insecure,
    /// The name is not a zone cut; it belongs to the parent zone.
    NotACut,
}

impl Denial {
    pub(super) fn new(max_iterations: u16) -> Self {
        Self {
            max_iterations,
            ..Self::default()
        }
    }

    /// Adds the verified NSEC/NSEC3 records of `rrset`, signed by `zone`. NSEC3 records with
    /// an unknown hash algorithm or a malformed owner hash are ignored (RFC 5155 8.1), as are
    /// those with flag bits other than Opt-Out set (RFC 5155 8.2: flags other than 0 or 1).
    pub(super) fn add(&mut self, rrset: &[Record], zone: &Name) {
        for r in rrset {
            match &r.data {
                RData::Nsec { next, types } => self.nsec.push(NsecRec {
                    owner: r.name.clone(),
                    next: next.clone(),
                    types: types.clone(),
                    zone: zone.clone(),
                }),
                RData::Nsec3(n) if n.hash_alg == NSEC3_SHA1 && n.flags & !NSEC3_OPT_OUT == 0 => {
                    let hash = r
                        .name
                        .labels()
                        .next()
                        .and_then(|l| std::str::from_utf8(l).ok())
                        .and_then(|l| base32hex_decode(l).ok());
                    if let (Some(hash), Some(parent)) = (hash, r.name.parent())
                        && hash.len() == 20
                        && parent == *zone
                    {
                        self.nsec3.push(Nsec3Rec {
                            hash,
                            zone: zone.clone(),
                            rec: n.clone(),
                        });
                    }
                }
                _ => {}
            }
        }
    }

    /// Only the records signed by `zone`: a proof never mixes records of different zones.
    pub(super) fn for_zone(&self, zone: &Name) -> Denial {
        Denial {
            nsec: self
                .nsec
                .iter()
                .filter(|r| &r.zone == zone)
                .cloned()
                .collect(),
            nsec3: self
                .nsec3
                .iter()
                .filter(|r| &r.zone == zone)
                .cloned()
                .collect(),
            max_iterations: self.max_iterations,
        }
    }

    /// The deepest zone with denial records enclosing `name`. A deeper zone hidden by the
    /// sender cannot be skipped: the parent's records show the delegation, and the delegation
    /// rules make such a proof fail.
    pub(super) fn deepest_zone(&self, name: &Name) -> Option<Name> {
        self.nsec
            .iter()
            .map(|r| &r.zone)
            .chain(self.nsec3.iter().map(|r| &r.zone))
            .filter(|z| name.is_subdomain_of(z))
            .max_by_key(|z| z.label_count())
            .cloned()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.nsec.is_empty() && self.nsec3.is_empty()
    }

    /// RFC 9276 3.2: NSEC3 records above the iteration limit make the answer insecure.
    fn too_many_iterations(&self, name: &Name) -> bool {
        self.nsec3
            .iter()
            .any(|r| name.is_subdomain_of(&r.zone) && r.rec.iterations > self.max_iterations)
    }

    /// NSEC proves names in its zone; NSEC3 is used when no NSEC zone encloses `name`.
    fn uses_nsec(&self, name: &Name) -> bool {
        self.nsec.iter().any(|r| name.is_subdomain_of(&r.zone))
    }

    /// Proves that `name` does not exist (NXDOMAIN).
    pub(super) fn nxdomain(&self, name: &Name, h: &mut Hasher) -> Res<Verdict> {
        if self.too_many_iterations(name) {
            return Ok(Verdict::Insecure(None));
        }
        if self.uses_nsec(name) {
            if self.nsec.iter().any(|r| &r.owner == name) {
                return Err(Failure::bogus(
                    ede::DNSSEC_BOGUS,
                    "NSEC shows the name exists",
                ));
            }
            let cover = self.nsec_cover(name)?;
            let wildcard = wildcard_of(&closest_encloser(name, cover))?;
            if self.nsec.iter().any(|r| r.owner == wildcard) {
                return Err(Failure::bogus(
                    ede::DNSSEC_BOGUS,
                    "NSEC shows a wildcard exists",
                ));
            }
            self.nsec_cover(&wildcard)?;
            return Ok(Verdict::Secure);
        }
        if self.nsec3_match(name, h)?.is_some() {
            return Err(Failure::bogus(
                ede::DNSSEC_BOGUS,
                "NSEC3 shows the name exists",
            ));
        }
        let (ce, nc) = self
            .nsec3_closest_encloser(name, h)?
            .ok_or_else(|| missing("no NSEC3 closest encloser proof"))?;
        let wildcard = wildcard_of(&ce)?;
        if !self.nsec3_covered(&wildcard, h)? {
            return Err(missing("no NSEC3 covers the wildcard"));
        }
        if self.nsec3[nc].opt_out() {
            return Ok(Verdict::Insecure(None));
        }
        Ok(Verdict::Secure)
    }

    /// Proves that `name` has no `qtype` records (NODATA), including empty non-terminals and
    /// wildcard NODATA.
    pub(super) fn nodata(&self, name: &Name, qtype: RecordType, h: &mut Hasher) -> Res<Verdict> {
        if self.too_many_iterations(name) {
            return Ok(Verdict::Insecure(None));
        }
        if self.uses_nsec(name) {
            if let Some(r) = self.nsec.iter().find(|r| &r.owner == name) {
                check_bitmap(&r.types, qtype)?;
                return Ok(Verdict::Secure);
            }
            let cover = self.nsec_cover(name)?;
            if cover.next != *name && cover.next.is_subdomain_of(name) {
                return Ok(Verdict::Secure); // empty non-terminal
            }
            let wildcard = wildcard_of(&closest_encloser(name, cover))?;
            let r = self
                .nsec
                .iter()
                .find(|r| r.owner == wildcard)
                .ok_or_else(|| missing("no NSEC proves NODATA"))?;
            check_bitmap(&r.types, qtype)?;
            return Ok(Verdict::Secure);
        }
        if let Some(i) = self.nsec3_match(name, h)? {
            check_bitmap(&self.nsec3[i].rec.types, qtype)?;
            return Ok(Verdict::Secure);
        }
        let (ce, nc) = self
            .nsec3_closest_encloser(name, h)?
            .ok_or_else(|| missing("no NSEC3 proves NODATA"))?;
        if qtype == RecordType::Ds && self.nsec3[nc].opt_out() {
            return Ok(Verdict::Insecure(None));
        }
        let i = self
            .nsec3_match(&wildcard_of(&ce)?, h)?
            .ok_or_else(|| missing("no NSEC3 proves NODATA"))?;
        check_bitmap(&self.nsec3[i].rec.types, qtype)?;
        Ok(Verdict::Secure)
    }

    /// What the absence of a DS `RRset` at `name` proves (used while walking the chain).
    pub(super) fn ds_absence(&self, name: &Name, h: &mut Hasher) -> Res<Cut> {
        if self.too_many_iterations(name) {
            return Ok(Cut::Insecure);
        }
        if self.uses_nsec(name) {
            if let Some(r) = self.nsec.iter().find(|r| &r.owner == name) {
                return cut_from_bitmap(&r.types);
            }
            self.nsec_cover(name)?;
            return Ok(Cut::NotACut);
        }
        if let Some(i) = self.nsec3_match(name, h)? {
            return cut_from_bitmap(&self.nsec3[i].rec.types);
        }
        let (_, nc) = self
            .nsec3_closest_encloser(name, h)?
            .ok_or_else(|| missing("no NSEC3 proves the DS absence"))?;
        Ok(if self.nsec3[nc].opt_out() {
            Cut::Insecure
        } else {
            Cut::NotACut
        })
    }

    /// Proves that a wildcard expansion was legitimate: the next closer name of `name`
    /// below the closest encloser (the RRSIG's rightmost `labels` labels) does not exist
    /// (RFC 4035 5.3.4, RFC 5155 8.8).
    pub(super) fn wildcard_expansion(
        &self,
        name: &Name,
        labels: u8,
        h: &mut Hasher,
    ) -> Res<Verdict> {
        if self.too_many_iterations(name) {
            return Ok(Verdict::Insecure(None));
        }
        if self.uses_nsec(name) {
            // The covering NSEC must also show that the wildcard's parent is the closest
            // encloser, so no closer name could have answered instead.
            let cover = self.nsec_cover(name)?;
            if closest_encloser(name, cover).label_count() != labels {
                return Err(Failure::bogus(
                    ede::DNSSEC_BOGUS,
                    "NSEC closest encloser does not match the wildcard",
                ));
            }
            return Ok(Verdict::Secure);
        }
        let next_closer = suffix(name, labels.saturating_add(1));
        // RFC 5155 8.8, 6.1: an opt-out span may hold unsigned delegations, so the next
        // closer name is not proven absent and the expansion cannot be called secure.
        match self.nsec3_cover(&next_closer, h)? {
            Some(i) if self.nsec3[i].opt_out() => Ok(Verdict::Insecure(None)),
            Some(_) => Ok(Verdict::Secure),
            None => Err(missing("no denial proves the wildcard expansion")),
        }
    }

    fn nsec_cover(&self, name: &Name) -> Res<&NsecRec> {
        self.nsec
            .iter()
            .find(|r| r.covers(name))
            .ok_or_else(|| missing(format!("no NSEC covers {name}")))
    }

    fn nsec3_match(&self, name: &Name, h: &mut Hasher) -> Res<Option<usize>> {
        for (i, r) in self.nsec3.iter().enumerate() {
            if r.matches(name, h)? {
                return Ok(Some(i));
            }
        }
        Ok(None)
    }

    fn nsec3_cover(&self, name: &Name, h: &mut Hasher) -> Res<Option<usize>> {
        for (i, r) in self.nsec3.iter().enumerate() {
            if r.covers(name, h)? {
                return Ok(Some(i));
            }
        }
        Ok(None)
    }

    fn nsec3_covered(&self, name: &Name, h: &mut Hasher) -> Res<bool> {
        Ok(self.nsec3_cover(name, h)?.is_some())
    }

    /// RFC 5155 8.3: the deepest ancestor of `name` with a matching NSEC3 (the closest
    /// encloser) and the NSEC3 covering the next closer name. The closest encloser must not
    /// be a delegation or a DNAME owner.
    fn nsec3_closest_encloser(&self, name: &Name, h: &mut Hasher) -> Res<Option<(Name, usize)>> {
        let mut next_closer = name.clone();
        while let Some(ce) = next_closer.parent() {
            if !self.nsec3.iter().any(|r| ce.is_subdomain_of(&r.zone)) {
                return Ok(None);
            }
            if let Some(i) = self.nsec3_match(&ce, h)? {
                let types = &self.nsec3[i].rec.types;
                if is_delegation(types) || types.contains(DNAME) {
                    return Err(Failure::bogus(
                        ede::DNSSEC_BOGUS,
                        "NSEC3 closest encloser is a delegation or DNAME",
                    ));
                }
                return match self.nsec3_cover(&next_closer, h)? {
                    Some(nc) => Ok(Some((ce, nc))),
                    None => Err(missing("no NSEC3 covers the next closer name")),
                };
            }
            next_closer = ce;
        }
        Ok(None)
    }
}

fn missing(text: impl Into<String>) -> Failure {
    Failure::bogus(ede::NSEC_MISSING, text)
}

fn is_delegation(types: &TypeBitmap) -> bool {
    types.contains(RecordType::Ns) && !types.contains(RecordType::Soa)
}

/// A NODATA bitmap must not list `qtype` or CNAME. Only a parent-side delegation NSEC proves
/// a missing DS; only a child-side one proves anything else (RFC 6840 4.4).
fn check_bitmap(types: &TypeBitmap, qtype: RecordType) -> Res<()> {
    if types.contains(qtype) || types.contains(RecordType::Cname) {
        return Err(Failure::bogus(
            ede::DNSSEC_BOGUS,
            format!("denial bitmap lists {qtype:?} or CNAME"),
        ));
    }
    let child_apex = qtype == RecordType::Ds && types.contains(RecordType::Soa);
    let parent_side = qtype != RecordType::Ds && is_delegation(types);
    if child_apex || parent_side {
        return Err(Failure::bogus(
            ede::DNSSEC_BOGUS,
            "denial record from the wrong side of a zone cut",
        ));
    }
    Ok(())
}

fn cut_from_bitmap(types: &TypeBitmap) -> Res<Cut> {
    if types.contains(RecordType::Ds) || types.contains(RecordType::Soa) {
        return Err(Failure::bogus(
            ede::DNSSEC_BOGUS,
            "denial record does not prove the DS absence",
        ));
    }
    Ok(if types.contains(RecordType::Ns) {
        Cut::Insecure
    } else {
        Cut::NotACut
    })
}

/// The rightmost `n` labels of `name`.
pub(super) fn suffix(name: &Name, n: u8) -> Name {
    let skip = name.label_count().saturating_sub(n);
    Name::from_labels(name.labels().skip(usize::from(skip))).unwrap_or_else(|_| name.clone())
}

fn common_ancestor(a: &Name, b: &Name) -> Name {
    let mut n = a.clone();
    while !b.is_subdomain_of(&n) {
        match n.parent() {
            Some(p) => n = p,
            None => break,
        }
    }
    n
}

/// RFC 4035 5.4: the closest encloser implied by an NSEC covering `name`.
fn closest_encloser(name: &Name, cover: &NsecRec) -> Name {
    let a = common_ancestor(name, &cover.owner);
    let b = common_ancestor(name, &cover.next);
    let ce = if a.label_count() >= b.label_count() {
        a
    } else {
        b
    };
    if ce.is_subdomain_of(&cover.zone) {
        ce
    } else {
        cover.zone.clone()
    }
}

fn wildcard_of(ce: &Name) -> Res<Name> {
    let labels = std::iter::once(&b"*"[..]).chain(ce.labels());
    Name::from_labels(labels)
        .map_err(|_| Failure::bogus(ede::DNSSEC_BOGUS, "wildcard name is too long"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn nsec(owner: &str, next: &str, types: &[RecordType]) -> NsecRec {
        NsecRec {
            owner: n(owner),
            next: n(next),
            types: TypeBitmap::from_types(types),
            zone: n("example."),
        }
    }

    #[test]
    fn nsec_cover_handles_wrap_and_zone() {
        let last = nsec("z.example.", "example.", &[RecordType::A]);
        assert!(last.covers(&n("zz.example.")));
        assert!(!last.covers(&n("a.example.")));
        assert!(!last.covers(&n("zz.other.")));
        let mid = nsec("a.example.", "c.example.", &[RecordType::A]);
        assert!(mid.covers(&n("b.example.")));
        assert!(mid.covers(&n("x.a.example.")));
        assert!(!mid.covers(&n("a.example.")));
    }

    #[test]
    fn delegation_nsec_does_not_cover_names_below() {
        let cut = nsec("a.example.", "c.example.", &[RecordType::Ns]);
        assert!(!cut.covers(&n("x.a.example.")));
        assert!(cut.covers(&n("b.example.")));
        let dname = nsec("a.example.", "c.example.", &[DNAME]);
        assert!(!dname.covers(&n("x.a.example.")));
    }

    #[test]
    fn helpers() {
        assert_eq!(suffix(&n("a.b.c."), 2), n("b.c."));
        assert_eq!(suffix(&n("a.b.c."), 9), n("a.b.c."));
        assert_eq!(common_ancestor(&n("a.b.c."), &n("x.c.")), n("c."));
        assert_eq!(common_ancestor(&n("a."), &n("b.")), Name::root());
        assert_eq!(wildcard_of(&n("example.")).unwrap(), n("*.example."));
        let a63 = "a".repeat(63);
        let long = n(&format!("{a63}.{a63}.{a63}.{}.", "a".repeat(61)));
        assert!(wildcard_of(&long).is_err());
        let cover = nsec("a.example.", "c.example.", &[RecordType::A]);
        assert_eq!(closest_encloser(&n("b.example."), &cover), n("example."));
        let foreign = NsecRec {
            zone: n("sub.example."),
            ..nsec("a.example.", "c.example.", &[])
        };
        assert_eq!(
            closest_encloser(&n("b.example."), &foreign),
            n("sub.example.")
        );
    }

    #[test]
    fn bitmap_rules() {
        let t = |ts: &[RecordType]| TypeBitmap::from_types(ts);
        assert!(check_bitmap(&t(&[RecordType::Aaaa]), RecordType::A).is_ok());
        assert!(check_bitmap(&t(&[RecordType::A]), RecordType::A).is_err());
        assert!(check_bitmap(&t(&[RecordType::Cname]), RecordType::A).is_err());
        assert!(check_bitmap(&t(&[RecordType::Ns]), RecordType::A).is_err());
        assert!(check_bitmap(&t(&[RecordType::Ns, RecordType::Soa]), RecordType::A).is_ok());
        assert!(check_bitmap(&t(&[RecordType::Ns]), RecordType::Ds).is_ok());
        assert!(check_bitmap(&t(&[RecordType::Ns, RecordType::Soa]), RecordType::Ds).is_err());
        assert_eq!(cut_from_bitmap(&t(&[RecordType::Ns])), Ok(Cut::Insecure));
        assert_eq!(cut_from_bitmap(&t(&[RecordType::A])), Ok(Cut::NotACut));
        assert!(cut_from_bitmap(&t(&[RecordType::Ns, RecordType::Ds])).is_err());
        assert!(cut_from_bitmap(&t(&[RecordType::Ns, RecordType::Soa])).is_err());
    }

    #[test]
    fn hasher_memoises_and_enforces_budget() {
        let mut h = Hasher::new(1);
        let a = h.hash(&n("a.example."), b"", 0).unwrap();
        assert_eq!(h.hash(&n("A.example."), b"", 0).unwrap(), a);
        assert!(h.hash(&n("b.example."), b"", 0).is_err());
    }

    #[test]
    fn nsec3_records_with_bad_owner_or_alg_are_ignored() {
        let zone = n("example.");
        let rec = |owner: &str, alg: u8| Record {
            name: n(owner),
            rtype: RecordType::Nsec3,
            class: dnsy_proto::Class::In,
            ttl: 1,
            data: RData::Nsec3(Nsec3 {
                hash_alg: alg,
                flags: 0,
                iterations: 0,
                salt: vec![],
                next_hashed: vec![0; 20],
                types: TypeBitmap::default(),
            }),
        };
        let good = format!("{}.example.", "0".repeat(32));
        let mut d = Denial::new(100);
        d.add(
            &[
                rec(&good, 2),
                rec("zz.example.", 1),
                rec(&format!("{}.sub.example.", "0".repeat(32)), 1),
                rec("0000.example.", 1),
            ],
            &zone,
        );
        assert!(d.is_empty());
        d.add(&[rec(&good, 1)], &zone);
        assert!(!d.is_empty());
    }

    #[test]
    fn nsec3_records_with_unknown_flag_bits_are_ignored() {
        let zone = n("example.");
        let rec = |flags: u8| Record {
            name: n(&format!("{}.example.", "0".repeat(32))),
            rtype: RecordType::Nsec3,
            class: dnsy_proto::Class::In,
            ttl: 1,
            data: RData::Nsec3(Nsec3 {
                hash_alg: 1,
                flags,
                iterations: 0,
                salt: vec![],
                next_hashed: vec![0; 20],
                types: TypeBitmap::default(),
            }),
        };
        // RFC 5155 8.2: a flags value other than 0 or 1 makes the record unusable.
        for flags in [0x02, 0x80, 0x03, 0xff] {
            let mut d = Denial::new(100);
            d.add(&[rec(flags)], &zone);
            assert!(d.is_empty(), "flags {flags:#04x}");
        }
        for flags in [0x00, NSEC3_OPT_OUT] {
            let mut d = Denial::new(100);
            d.add(&[rec(flags)], &zone);
            assert!(!d.is_empty(), "flags {flags:#04x}");
        }
    }
}
