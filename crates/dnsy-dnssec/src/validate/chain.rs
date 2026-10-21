//! The chain of trust: from the closest trust anchor down to a signer zone (RFC 4035 5),
//! proving insecure delegations on the way.

use std::collections::HashMap;

use super::denial::{Cut, Denial, Hasher};
use super::rrset::{rrset_at, sigs_for, ttl_cap};
use super::{DnssecFetcher, Failure, Res, Validator, Verdict};
use crate::{Algorithm, DigestType, ds_for};
use dnsy_proto::{Class, Dnskey, Ds, Message, Name, Question, RData, Record, RecordType, ede};

/// What is known about the zone a name belongs to.
#[derive(Debug, Clone)]
pub(super) enum Trust {
    /// `zone` is signed and `keys` is its validated DNSKEY `RRset` (zone keys only).
    Secure { zone: Name, keys: Vec<Dnskey> },
    /// The name is below an insecure delegation or a zone using only unsupported algorithms.
    Insecure(Option<(u16, String)>),
}

/// Per-validation state: the fetch memo, the trust memo and the work counters.
pub(super) struct Ctx<'a, F> {
    pub(super) validator: &'a Validator,
    fetcher: &'a F,
    pub(super) now: u32,
    fetched: HashMap<(Name, RecordType), Message>,
    fetches: usize,
    pub(super) verifications: usize,
    trust: HashMap<Name, Trust>,
    pub(super) hasher: Hasher,
    min_ttl: Option<u32>,
    /// Wildcard expansions seen among validated `RRsets`: (owner, RRSIG labels, signer).
    pub(super) wildcards: Vec<(Name, u8, Name)>,
}

impl<'a, F: DnssecFetcher> Ctx<'a, F> {
    pub(super) fn new(validator: &'a Validator, fetcher: &'a F, now: u32) -> Self {
        Self {
            validator,
            fetcher,
            now,
            fetched: HashMap::new(),
            fetches: 0,
            verifications: 0,
            trust: HashMap::new(),
            hasher: Hasher::new(validator.limits.max_nsec3_hashes),
            min_ttl: None,
            wildcards: Vec::new(),
        }
    }

    pub(super) fn min_ttl(&self) -> Option<u32> {
        self.min_ttl
    }

    fn note_ttl(&mut self, ttl: u32) {
        self.min_ttl = Some(self.min_ttl.map_or(ttl, |m| m.min(ttl)));
    }

    pub(super) fn denial(&self) -> Denial {
        Denial::new(self.validator.limits.max_nsec3_iterations)
    }

    async fn fetch(&mut self, name: &Name, qtype: RecordType) -> Res<Message> {
        let key = (name.to_lowercase(), qtype);
        if let Some(m) = self.fetched.get(&key) {
            return Ok(m.clone());
        }
        if self.fetches >= self.validator.limits.max_fetches {
            return Err(Failure::limit("fetches"));
        }
        self.fetches += 1;
        let q = Question {
            name: name.clone(),
            qtype,
            qclass: Class::In,
        };
        let m = self.fetcher.fetch(q).await.map_err(|e| {
            let code = if qtype == RecordType::Dnskey {
                ede::DNSKEY_MISSING
            } else {
                ede::DNSSEC_BOGUS
            };
            Failure::bogus(code, format!("{qtype:?} {name}: {e}"))
        })?;
        self.fetched.insert(key, m.clone());
        Ok(m)
    }

    /// Validates one `RRset` taken from `section` of the response. Returns the verdict and,
    /// when it is `Secure`, the zone that signed it.
    pub(super) async fn rrset(
        &mut self,
        rrset: &[Record],
        section: &[Record],
    ) -> Res<(Verdict, Option<Name>)> {
        let owner = &rrset[0].name;
        if self.validator.anchors.is_negative(owner, self.now) {
            return Ok((Verdict::Insecure(None), None));
        }
        let anchor = self.closest_anchor(owner)?;
        let sigs: Vec<_> = sigs_for(section, owner, rrset[0].rtype)
            .into_iter()
            .filter(|s| owner.is_subdomain_of(&s.signer) && s.signer.is_subdomain_of(&anchor))
            .collect();
        let Some(signer) = sigs
            .iter()
            .map(|s| s.signer.clone())
            .max_by_key(Name::label_count)
        else {
            return match self.trust_for(owner).await? {
                Trust::Insecure(e) => Ok((Verdict::Insecure(e), None)),
                Trust::Secure { zone, .. } => Err(Failure::bogus(
                    ede::RRSIGS_MISSING,
                    format!(
                        "{owner} {:?} is unsigned in secure zone {zone}",
                        rrset[0].rtype
                    ),
                )),
            };
        };
        let (zone, keys) = match self.trust_for(&signer).await? {
            Trust::Insecure(e) => return Ok((Verdict::Insecure(e), None)),
            Trust::Secure { zone, keys } => (zone, keys),
        };
        if zone != signer {
            return Err(Failure::bogus(
                ede::DNSSEC_BOGUS,
                format!("RRSIG signer {signer} is not a zone apex"),
            ));
        }
        let sigs: Vec<_> = sigs.into_iter().filter(|s| s.signer == signer).collect();
        let sig = self.verify_with(rrset, &sigs, &keys)?;
        self.note_ttl(ttl_cap(rrset, &sig, self.now));
        let literal_wildcard =
            owner.labels().next() == Some(b"*".as_slice()) && sig.labels + 1 == owner.label_count();
        if sig.labels < owner.label_count() && !literal_wildcard {
            self.wildcards
                .push((owner.clone(), sig.labels, signer.clone()));
        }
        Ok((Verdict::Secure, Some(signer)))
    }

    pub(super) fn closest_anchor(&self, name: &Name) -> Res<Name> {
        self.validator
            .anchors
            .closest(name)
            .cloned()
            .ok_or_else(|| Failure::indeterminate(format!("no trust anchor covers {name}")))
    }

    /// The trust state of the zone containing `target`: walks up from `target` with DS
    /// queries until a known zone or the closest anchor, then validates back down.
    pub(super) async fn trust_for(&mut self, target: &Name) -> Res<Trust> {
        let anchor = self.closest_anchor(target)?;
        let mut steps: Vec<(Name, Message)> = Vec::new();
        let mut cur = target.clone();
        let mut trust = loop {
            if let Some(t) = self.trust.get(&cur) {
                break t.clone();
            }
            if cur == anchor {
                let t = self.anchor_trust(&anchor).await?;
                self.trust.insert(cur.clone(), t.clone());
                break t;
            }
            if steps.len() >= self.validator.limits.max_zone_cuts {
                return Err(Failure::limit("zone cuts"));
            }
            let resp = self.fetch(&cur, RecordType::Ds).await?;
            let next = parent_hint(&resp, &cur, &anchor);
            steps.push((cur, resp));
            cur = next;
        };
        while let Some((name, resp)) = steps.pop() {
            trust = self.step(trust, &name, &resp).await?;
            self.trust.insert(name, trust.clone());
        }
        Ok(trust)
    }

    /// One level down: given the trust of the zone above `name` and the DS response for
    /// `name`, the trust of `name`.
    async fn step(&mut self, parent: Trust, name: &Name, resp: &Message) -> Res<Trust> {
        let Trust::Secure { zone, keys } = parent else {
            return Ok(parent);
        };
        let ds_rrset = rrset_at(&resp.answers, name, RecordType::Ds);
        if !ds_rrset.is_empty() {
            let sigs: Vec<_> = sigs_for(&resp.answers, name, RecordType::Ds)
                .into_iter()
                .filter(|s| s.signer == zone)
                .collect();
            self.verify_with(&ds_rrset, &sigs, &keys)?;
            let ds: Vec<Ds> = ds_rrset
                .iter()
                .filter_map(|r| match &r.data {
                    RData::Ds(d) => Some(d.clone()),
                    _ => None,
                })
                .collect();
            return self.child_trust(name, &ds, &[]).await;
        }
        let mut denial = self.denial();
        for set in super::rrset::rrsets(&resp.authority) {
            if !matches!(set[0].rtype, RecordType::Nsec | RecordType::Nsec3) {
                continue;
            }
            let sigs: Vec<_> = sigs_for(&resp.authority, &set[0].name, set[0].rtype)
                .into_iter()
                .filter(|s| s.signer == zone)
                .collect();
            if sigs.is_empty() {
                continue;
            }
            self.verify_with(&set, &sigs, &keys)?;
            denial.add(&set, &zone);
        }
        if denial.is_empty() {
            let signed = resp
                .answers
                .iter()
                .chain(&resp.authority)
                .any(|r| r.rtype == RecordType::Rrsig);
            let code = if signed {
                ede::NSEC_MISSING
            } else {
                ede::RRSIGS_MISSING
            };
            return Err(Failure::bogus(
                code,
                format!("no signed proof of the DS status of {name} from {zone}"),
            ));
        }
        Ok(match denial.ds_absence(name, &mut self.hasher)? {
            Cut::Insecure => Trust::Insecure(None),
            Cut::NotACut => Trust::Secure { zone, keys },
        })
    }

    /// The trust of the zone at `name` given its DS set (or DNSKEY anchors).
    async fn child_trust(&mut self, name: &Name, ds: &[Ds], anchor_keys: &[Dnskey]) -> Res<Trust> {
        let mut usable: Vec<&Ds> = ds
            .iter()
            .filter(|d| {
                Algorithm::from(d.algorithm).is_supported()
                    && !matches!(DigestType::from(d.digest_type), DigestType::Unsupported(_))
            })
            .collect();
        // RFC 4509 3: ignore SHA-1 DS records when a SHA-256 one is present.
        if usable
            .iter()
            .any(|d| d.digest_type == DigestType::Sha256.number())
        {
            usable.retain(|d| d.digest_type != DigestType::Sha1.number());
        }
        let keys: Vec<&Dnskey> = anchor_keys
            .iter()
            .filter(|k| Algorithm::from(k.algorithm).is_supported())
            .collect();
        if usable.is_empty() && keys.is_empty() {
            let alg_ok = ds
                .iter()
                .any(|d| Algorithm::from(d.algorithm).is_supported());
            let (code, text) = if alg_ok {
                (
                    ede::UNSUPPORTED_DS_DIGEST,
                    "only unsupported DS digest types",
                )
            } else {
                (
                    ede::UNSUPPORTED_DNSKEY_ALG,
                    "only unsupported DNSSEC algorithms",
                )
            };
            return Ok(Trust::Insecure(Some((code, format!("{name}: {text}")))));
        }
        let resp = self.fetch(name, RecordType::Dnskey).await?;
        let rrset = rrset_at(&resp.answers, name, RecordType::Dnskey);
        let all: Vec<Dnskey> = rrset
            .iter()
            .filter_map(|r| match &r.data {
                RData::Dnskey(k) if k.is_zone_key() => Some(k.clone()),
                _ => None,
            })
            .collect();
        if all.is_empty() {
            return Err(Failure::bogus(
                ede::DNSKEY_MISSING,
                format!("no DNSKEY RRset at {name}"),
            ));
        }
        // DS digests are charged to the verification budget: colliding key tags must not
        // buy unbounded hashing.
        let mut trusted: Vec<Dnskey> = Vec::new();
        for k in &all {
            let tag = k.key_tag();
            let mut matched = keys.contains(&k);
            for d in usable
                .iter()
                .filter(|d| d.key_tag == tag && d.algorithm == k.algorithm)
            {
                if matched {
                    break;
                }
                if self.verifications >= self.validator.limits.max_verifications {
                    return Err(Failure::limit("DS digest computations"));
                }
                self.verifications += 1;
                matched = ds_for(name, k, DigestType::from(d.digest_type))
                    .is_ok_and(|c| c.digest == d.digest);
            }
            if matched {
                trusted.push(k.clone());
            }
        }
        if trusted.is_empty() {
            return Err(Failure::bogus(
                ede::DNSKEY_MISSING,
                format!("no DNSKEY at {name} matches the DS or trust anchor"),
            ));
        }
        let sigs: Vec<_> = sigs_for(&resp.answers, name, RecordType::Dnskey)
            .into_iter()
            .filter(|s| &s.signer == name)
            .collect();
        self.verify_with(&rrset, &sigs, &trusted)?;
        Ok(Trust::Secure {
            zone: name.clone(),
            keys: all,
        })
    }

    async fn anchor_trust(&mut self, anchor: &Name) -> Res<Trust> {
        let anchors = &self.validator.anchors;
        let ds: Vec<Ds> = anchors.ds_at(anchor).cloned().collect();
        let keys: Vec<Dnskey> = anchors.keys_at(anchor).cloned().collect();
        self.child_trust(anchor, &ds, &keys).await
    }
}

/// The zone above `cur` that the DS response points at: the signer of the DS or denial
/// RRSIGs, else the SOA owner, else the parent name. Always a proper ancestor of `cur` at or
/// below the anchor, so the walk terminates.
fn parent_hint(resp: &Message, cur: &Name, anchor: &Name) -> Name {
    let ok = |n: &Name| n != cur && cur.is_subdomain_of(n) && n.is_subdomain_of(anchor);
    let signer = resp
        .answers
        .iter()
        .chain(&resp.authority)
        .filter_map(|r| match &r.data {
            RData::Rrsig(s)
                if matches!(
                    s.type_covered,
                    RecordType::Ds | RecordType::Nsec | RecordType::Nsec3
                ) =>
            {
                Some(s.signer.clone())
            }
            _ => None,
        })
        .find(|n| ok(n));
    let soa = || {
        resp.authority
            .iter()
            .filter(|r| r.rtype == RecordType::Soa)
            .map(|r| r.name.clone())
            .find(|n| ok(n))
    };
    signer
        .or_else(soa)
        .or_else(|| cur.parent())
        .unwrap_or_else(|| anchor.clone())
}
