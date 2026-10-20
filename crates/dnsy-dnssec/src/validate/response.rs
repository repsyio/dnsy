//! Response classification: the answer chain (CNAME and DNAME links validated one by one),
//! negative answers and wildcard expansion proofs.

use super::chain::{Ctx, Trust};
use super::denial::Denial;
use super::rrset::rrsets;
use super::{DnssecFetcher, Failure, Res, Verdict};
use dnsy_proto::{Message, Name, Question, RData, Rcode, Record, RecordType, WireReader, ede};

const DNAME: RecordType = RecordType::Unknown(39);

impl<F: DnssecFetcher> Ctx<'_, F> {
    pub(super) async fn response(&mut self, q: &Question, resp: &Message) -> Res<Verdict> {
        if self.validator.anchors.is_negative(&q.name) {
            return Ok(Verdict::Insecure(None));
        }
        let nxdomain = match resp.header.rcode {
            Rcode::NoError => false,
            Rcode::NxDomain => true,
            other => {
                return Err(Failure::indeterminate(format!(
                    "rcode {other:?} carries no data to validate"
                )));
            }
        };
        self.closest_anchor(&q.name)?;
        let (mut verdict, sname, answered) = self.answer_chain(q, resp).await?;

        let wildcards = std::mem::take(&mut self.wildcards);
        if answered && wildcards.is_empty() {
            return Ok(verdict);
        }
        let denial = self.authority_denial(resp).await?;
        for (owner, labels, zone) in wildcards {
            // Only the zone that signed the expansion can prove it.
            let proof = denial.for_zone(&zone);
            if proof.is_empty() {
                return Err(Failure::bogus(
                    ede::NSEC_MISSING,
                    format!("no denial from {zone} proves the wildcard expansion of {owner}"),
                ));
            }
            verdict = verdict.and(proof.wildcard_expansion(&owner, labels, &mut self.hasher)?);
        }
        if answered {
            return Ok(verdict);
        }
        if self.validator.anchors.is_negative(&sname) {
            return Ok(verdict.and(Verdict::Insecure(None)));
        }
        let Some(zone) = denial.deepest_zone(&sname) else {
            return match self.trust_for(&sname).await? {
                Trust::Insecure(e) => Ok(verdict.and(Verdict::Insecure(e))),
                Trust::Secure { .. } => Err(Failure::bogus(
                    ede::NSEC_MISSING,
                    format!("no NSEC or NSEC3 proves the negative answer for {sname}"),
                )),
            };
        };
        let denial = denial.for_zone(&zone);
        let proof = if nxdomain {
            denial.nxdomain(&sname, &mut self.hasher)
        } else {
            denial.nodata(&sname, q.qtype, &mut self.hasher)
        };
        // A failed proof is still insecure when the name's own chain proves it (for example
        // after a CNAME from a signed zone into an unsigned one).
        let proof = match proof {
            Ok(v) => v,
            Err(f) => match self.trust_for(&sname).await {
                Ok(Trust::Insecure(e)) => Verdict::Insecure(e),
                _ => return Err(f),
            },
        };
        Ok(verdict.and(proof))
    }

    /// Follows the answer section from the question name through CNAME and DNAME links,
    /// validating each link, then validates the remaining answer `RRsets`. Returns the
    /// combined verdict, the final name and whether it was answered.
    async fn answer_chain(&mut self, q: &Question, resp: &Message) -> Res<(Verdict, Name, bool)> {
        let sets = rrsets(&resp.answers);
        let mut done = vec![false; sets.len()];
        let mut verdict = Verdict::Secure;
        let mut sname = q.name.clone();
        let mut answered = false;
        for _ in 0..=sets.len() {
            let direct: Vec<usize> = (0..sets.len())
                .filter(|&i| {
                    sets[i][0].name == sname
                        && (sets[i][0].rtype == q.qtype || q.qtype == RecordType::Any)
                })
                .collect();
            if !direct.is_empty() {
                for i in direct {
                    verdict = verdict.and(self.rrset(&sets[i], &resp.answers).await?.0);
                    done[i] = true;
                }
                answered = true;
                break;
            }
            if let Some(i) = (0..sets.len()).find(|&i| {
                let owner = &sets[i][0].name;
                !done[i]
                    && sets[i][0].rtype == DNAME
                    && owner != &sname
                    && sname.is_subdomain_of(owner)
            }) {
                verdict = verdict.and(self.rrset(&sets[i], &resp.answers).await?.0);
                done[i] = true;
                let next = dname_substitute(&sname, &sets[i][0])?;
                // The synthesized CNAME is unsigned (RFC 6672 5.3.1); it must match.
                if let Some(c) = (0..sets.len()).find(|&c| {
                    !done[c] && sets[c][0].name == sname && sets[c][0].rtype == RecordType::Cname
                }) {
                    if sets[c][0].data != RData::Cname(next.clone()) {
                        return Err(Failure::bogus(
                            ede::DNSSEC_BOGUS,
                            "synthesized CNAME does not match the DNAME",
                        ));
                    }
                    done[c] = true;
                }
                sname = next;
                continue;
            }
            if let Some(i) = (0..sets.len()).find(|&i| {
                !done[i] && sets[i][0].name == sname && sets[i][0].rtype == RecordType::Cname
            }) {
                verdict = verdict.and(self.rrset(&sets[i], &resp.answers).await?.0);
                done[i] = true;
                sname = match &sets[i][0].data {
                    RData::Cname(t) => t.clone(),
                    _ => return Err(Failure::bogus(ede::DNSSEC_BOGUS, "malformed CNAME")),
                };
                continue;
            }
            break;
        }
        // Records off the chain must not downgrade a secure chain to insecure.
        for i in 0..sets.len() {
            if done[i] {
                continue;
            }
            let extra = self.rrset(&sets[i], &resp.answers).await?.0;
            if verdict == Verdict::Secure && extra != Verdict::Secure {
                return Err(Failure::bogus(
                    ede::DNSSEC_BOGUS,
                    format!("unsigned {} outside the answer chain", sets[i][0].name),
                ));
            }
            verdict = verdict.and(extra);
        }

        Ok((verdict, sname, answered))
    }

    /// Validates the SOA, NSEC and NSEC3 `RRsets` of the authority section and collects the
    /// secure denial records. Insecure `RRsets` are left out: whether a negative answer is
    /// insecure is decided by the chain of the name itself, never by what an `RRset` claims.
    async fn authority_denial(&mut self, resp: &Message) -> Res<Denial> {
        let mut denial = self.denial();
        for set in rrsets(&resp.authority) {
            if !matches!(
                set[0].rtype,
                RecordType::Soa | RecordType::Nsec | RecordType::Nsec3
            ) {
                continue;
            }
            if let (Verdict::Secure, Some(zone)) = self.rrset(&set, &resp.authority).await? {
                denial.add(&set, &zone);
            }
        }
        Ok(denial)
    }
}

/// RFC 6672 2.2: replaces the DNAME owner suffix of `sname` with the DNAME target.
fn dname_substitute(sname: &Name, dname: &Record) -> Res<Name> {
    let bad = |why: &str| Failure::bogus(ede::DNSSEC_BOGUS, format!("DNAME: {why}"));
    let target = match &dname.data {
        RData::Opaque { data, .. } => WireReader::new(data)
            .read_name()
            .map_err(|_| bad("malformed target"))?,
        _ => return Err(bad("malformed record")),
    };
    let keep = usize::from(sname.label_count() - dname.name.label_count());
    Name::from_labels(sname.labels().take(keep).chain(target.labels()))
        .map_err(|_| bad("substituted name is too long"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnsy_proto::Class;

    fn dname(owner: &str, data: RData) -> Record {
        Record {
            name: Name::from_ascii(owner).unwrap(),
            rtype: DNAME,
            class: Class::In,
            ttl: 60,
            data,
        }
    }

    #[test]
    fn dname_substitution() {
        let target = Name::from_ascii("new.example.").unwrap();
        let r = dname(
            "old.example.",
            RData::Opaque {
                rtype: 39,
                data: target.as_wire().to_vec(),
            },
        );
        let s = Name::from_ascii("a.b.old.example.").unwrap();
        assert_eq!(
            dname_substitute(&s, &r).unwrap(),
            Name::from_ascii("a.b.new.example.").unwrap()
        );
        let garbage = dname(
            "old.example.",
            RData::Opaque {
                rtype: 39,
                data: vec![9],
            },
        );
        assert!(dname_substitute(&s, &garbage).is_err());
        let wrong = dname("old.example.", RData::Cname(target));
        assert!(dname_substitute(&s, &wrong).is_err());
        let a63 = "a".repeat(63);
        let long_target = Name::from_ascii(&format!("{a63}.{a63}.{a63}.")).unwrap();
        let long = dname(
            "old.example.",
            RData::Opaque {
                rtype: 39,
                data: long_target.as_wire().to_vec(),
            },
        );
        let deep = Name::from_ascii(&format!("{a63}.old.example.")).unwrap();
        assert!(dname_substitute(&deep, &long).is_err());
    }
}
