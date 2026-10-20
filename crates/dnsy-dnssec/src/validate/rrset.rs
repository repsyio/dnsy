//! `RRset` grouping and budgeted signature verification.

use super::chain::Ctx;
use super::{DnssecFetcher, Failure, Res};
use crate::{Algorithm, VerifyError, verify_rrsig_with_skew};
use dnsy_proto::{Dnskey, Name, RData, Record, RecordType, Rrsig, ede, serial_gt};

/// Groups a section into `RRsets` (owner, type, class), in order of first appearance.
/// RRSIG and OPT records are left out.
pub(super) fn rrsets(section: &[Record]) -> Vec<Vec<Record>> {
    let mut out: Vec<Vec<Record>> = Vec::new();
    for r in section {
        if matches!(r.rtype, RecordType::Rrsig | RecordType::Opt) {
            continue;
        }
        match out
            .iter_mut()
            .find(|s| s[0].name == r.name && s[0].rtype == r.rtype && s[0].class == r.class)
        {
            Some(set) => set.push(r.clone()),
            None => out.push(vec![r.clone()]),
        }
    }
    out
}

/// The records of type `rtype` owned by `owner`.
pub(super) fn rrset_at(section: &[Record], owner: &Name, rtype: RecordType) -> Vec<Record> {
    section
        .iter()
        .filter(|r| r.rtype == rtype && &r.name == owner)
        .cloned()
        .collect()
}

/// The RRSIGs in `section` covering `owner`/`rtype`.
pub(super) fn sigs_for(section: &[Record], owner: &Name, rtype: RecordType) -> Vec<Rrsig> {
    section
        .iter()
        .filter(|r| &r.name == owner)
        .filter_map(|r| match &r.data {
            RData::Rrsig(s) if s.type_covered == rtype => Some(s.clone()),
            _ => None,
        })
        .collect()
}

impl<F: DnssecFetcher> Ctx<'_, F> {
    /// Verifies `rrset` with one of `sigs` by one of `keys`. At most
    /// `max_rrsig_verifications` signature checks are attempted for the `RRset` and the
    /// validation-wide `max_verifications` budget is charged for each. Returns the RRSIG
    /// that verified.
    pub(super) fn verify_with(
        &mut self,
        rrset: &[Record],
        sigs: &[Rrsig],
        keys: &[Dnskey],
    ) -> Res<Rrsig> {
        if sigs.is_empty() {
            return Err(Failure::bogus(
                ede::RRSIGS_MISSING,
                "no RRSIG covers the RRset",
            ));
        }
        let limits = self.validator.limits;
        let mut tries = 0usize;
        let mut last: Option<VerifyError> = None;
        let tags: Vec<u16> = keys.iter().map(Dnskey::key_tag).collect();
        for sig in sigs {
            if !Algorithm::from(sig.algorithm).is_supported() {
                last.get_or_insert(VerifyError::UnsupportedAlgorithm(sig.algorithm));
                continue;
            }
            for (key, _) in keys
                .iter()
                .zip(&tags)
                .filter(|(k, t)| k.algorithm == sig.algorithm && **t == sig.key_tag)
            {
                if tries >= limits.max_rrsig_verifications {
                    return Err(Failure::limit("RRSIG verifications per RRset"));
                }
                if self.verifications >= limits.max_verifications {
                    return Err(Failure::limit("RRSIG verifications per validation"));
                }
                tries += 1;
                self.verifications += 1;
                match verify_rrsig_with_skew(rrset, sig, key, self.now, limits.clock_skew) {
                    Ok(()) => return Ok(sig.clone()),
                    Err(e) => last = Some(e),
                }
            }
        }
        Err(match last {
            None => Failure::bogus(
                ede::DNSKEY_MISSING,
                "no DNSKEY matches the RRSIG key tag and algorithm",
            ),
            Some(VerifyError::Expired) => {
                Failure::bogus(ede::SIGNATURE_EXPIRED, "RRSIG has expired")
            }
            Some(VerifyError::NotYetValid) => {
                Failure::bogus(ede::SIGNATURE_NOT_YET_VALID, "RRSIG is not yet valid")
            }
            Some(e) => Failure::bogus(ede::DNSSEC_BOGUS, e.to_string()),
        })
    }
}

/// Seconds a validated `RRset` may be cached: its lowest TTL, the original TTL and the time
/// left until the RRSIG expires.
pub(super) fn ttl_cap(rrset: &[Record], sig: &Rrsig, now: u32) -> u32 {
    let ttl = rrset.iter().map(|r| r.ttl).min().unwrap_or(0);
    let left = if serial_gt(sig.expiration, now) {
        sig.expiration.wrapping_sub(now)
    } else {
        0
    };
    ttl.min(sig.original_ttl).min(left)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnsy_proto::Class;
    use std::net::Ipv4Addr;

    fn a(owner: &str, ttl: u32) -> Record {
        Record {
            name: Name::from_ascii(owner).unwrap(),
            rtype: RecordType::A,
            class: Class::In,
            ttl,
            data: RData::A(Ipv4Addr::LOCALHOST),
        }
    }

    #[test]
    fn groups_by_owner_type_and_class() {
        let mut ch = a("x.example.", 1);
        ch.class = Class::Ch;
        let sets = rrsets(&[
            a("x.example.", 1),
            a("y.example.", 1),
            a("X.example.", 2),
            ch,
        ]);
        assert_eq!(sets.iter().map(Vec::len).collect::<Vec<_>>(), [2, 1, 1]);
    }

    #[test]
    fn ttl_cap_takes_the_minimum() {
        let sig = Rrsig {
            type_covered: RecordType::A,
            algorithm: 13,
            labels: 2,
            original_ttl: 100,
            expiration: 1_050,
            inception: 0,
            key_tag: 1,
            signer: Name::root(),
            signature: vec![1],
        };
        assert_eq!(ttl_cap(&[a("x.example.", 300)], &sig, 1_000), 50);
        assert_eq!(ttl_cap(&[a("x.example.", 30)], &sig, 1_000), 30);
        assert_eq!(ttl_cap(&[a("x.example.", 300)], &sig, 0), 100);
        assert_eq!(ttl_cap(&[a("x.example.", 300)], &sig, 1_100), 0);
    }
}
