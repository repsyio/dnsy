//! Canonical form of resource record sets for DNSSEC signing and validation (RFC 4034 6, RFC 6840 5.1).

use crate::{Name, RData, Record, Rrsig, WireWriter};

/// Canonical RDATA wire form: names of NS, CNAME, PTR, MX, SOA and SRV lowercased, no
/// name compression anywhere. Names inside NSEC and RRSIG are left as they are (RFC 6840
/// 5.1). RDATA that cannot be encoded (a CAA with an invalid tag) yields no octets.
pub fn rdata_wire(r: &RData) -> Vec<u8> {
    let mut w = WireWriter::new();
    match r {
        RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => name(&mut w, n),
        RData::Mx {
            preference,
            exchange,
        } => {
            w.write_u16(*preference);
            name(&mut w, exchange);
        }
        RData::Soa(soa) => {
            name(&mut w, &soa.mname);
            name(&mut w, &soa.rname);
            for v in [soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum] {
                w.write_u32(v);
            }
        }
        RData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            w.write_u16(*priority);
            w.write_u16(*weight);
            w.write_u16(*port);
            name(&mut w, target);
        }
        other => {
            if other.encode(&mut w).is_err() {
                return Vec::new();
            }
        }
    }
    w.finish()
}

fn name(w: &mut WireWriter, n: &Name) {
    w.write_bytes(n.to_lowercase().as_wire());
}

/// The owner name as signed: lowercased, and for a wildcard expansion (more labels than
/// the RRSIG `labels` field) replaced by `*.` plus the rightmost `labels` labels.
fn signing_owner(owner: &Name, labels: u8) -> Name {
    let owner = owner.to_lowercase();
    let count = owner.label_count();
    if count <= labels {
        return owner;
    }
    let kept = owner.labels().skip(usize::from(count - labels));
    let all = std::iter::once(&b"*"[..]).chain(kept);
    Name::from_labels(all).unwrap_or(owner)
}

/// The octets an RRSIG signature covers (RFC 4034 3.1.8.1): the RRSIG RDATA without the
/// signature, then every RR of `rrset` in canonical form ordered by RDATA (6.3, duplicates
/// removed), with the original TTL and wildcard owners restored from `rrsig.labels`.
pub fn rrset_signing_input(rrsig: &Rrsig, rrset: &[Record]) -> Vec<u8> {
    let mut rrs: Vec<(Vec<u8>, &Record)> = rrset.iter().map(|r| (rdata_wire(&r.data), r)).collect();
    rrs.sort_by(|a, b| a.0.cmp(&b.0));
    rrs.dedup_by(|a, b| a.0 == b.0);

    let mut out = rrsig.signed_prefix();
    for (rdata, record) in rrs {
        out.extend_from_slice(signing_owner(&record.name, rrsig.labels).as_wire());
        out.extend_from_slice(&u16::from(rrsig.type_covered).to_be_bytes());
        out.extend_from_slice(&u16::from(record.class).to_be_bytes());
        out.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
        out.extend_from_slice(&u16::try_from(rdata.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    out
}

#[cfg(test)]
mod tests;
