//! NSEC (RFC 4034 4, RFC 4035 2.3) and NSEC3 (RFC 5155 7.1) chains.

use crate::{DnssecError, nsec3_hash};
use dnsy_proto::{Class, Name, Nsec3, RData, Record, RecordType, TypeBitmap, base32hex_encode};
use std::collections::BTreeSet;

/// NSEC3 flag: this record may cover unsigned delegations (RFC 5155 3.1.2.1).
const OPT_OUT: u8 = 1;
/// NSEC3 hash algorithm 1, SHA-1 (RFC 5155 11).
pub(super) const NSEC3_SHA1: u8 = 1;

/// One name of the denial chain: the apex, authoritative names and delegation points, in
/// canonical order. Glue below a cut is not part of it.
pub(super) struct ChainNode {
    pub name: Name,
    /// Types at the name that are authoritative or mark a cut (NS, DS).
    pub types: Vec<RecordType>,
    /// Some `RRset` at the name is signed (all but insecure delegations).
    pub signed: bool,
    /// A delegation without DS.
    pub insecure_cut: bool,
}

/// The NSEC chain: one NSEC per node pointing at the next, the last back to the apex. The
/// bitmap adds NSEC and RRSIG, since the NSEC itself is signed at every node.
pub(super) fn nsec_chain(nodes: &[ChainNode], ttl: u32) -> Vec<Record> {
    nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let next = &nodes[(i + 1) % nodes.len()].name;
            let mut types = node.types.clone();
            types.extend([RecordType::Nsec, RecordType::Rrsig]);
            Record {
                name: node.name.clone(),
                rtype: RecordType::Nsec,
                class: Class::In,
                ttl,
                data: RData::Nsec {
                    next: next.to_lowercase(),
                    types: TypeBitmap::from_types(&types),
                },
            }
        })
        .collect()
}

/// The NSEC3 chain: hashed owners of every node and every empty non-terminal, sorted by
/// hash and linked in a ring. With opt-out, insecure delegations (and empty non-terminals
/// that exist only because of them) are left out and every record carries the opt-out flag.
pub(super) fn nsec3_chain(
    origin: &Name,
    nodes: &[ChainNode],
    ttl: u32,
    iterations: u16,
    salt: &[u8],
    opt_out: bool,
) -> Result<Vec<Record>, DnssecError> {
    let kept: Vec<&ChainNode> = nodes
        .iter()
        .filter(|n| !(opt_out && n.insecure_cut))
        .collect();
    let existing: BTreeSet<&Name> = kept.iter().map(|n| &n.name).collect();
    let mut empty: BTreeSet<Name> = BTreeSet::new();
    for node in &kept {
        let mut name = node.name.parent();
        while let Some(parent) = name {
            if !parent.is_subdomain_of(origin) || parent == *origin {
                break;
            }
            if !existing.contains(&parent) {
                empty.insert(parent.clone());
            }
            name = parent.parent();
        }
    }

    let mut hashed: Vec<([u8; 20], TypeBitmap)> = kept
        .iter()
        .map(|n| {
            let mut types = n.types.clone();
            if n.signed {
                types.push(RecordType::Rrsig);
            }
            (
                nsec3_hash(&n.name, salt, iterations),
                TypeBitmap::from_types(&types),
            )
        })
        .chain(
            empty
                .iter()
                .map(|n| (nsec3_hash(n, salt, iterations), TypeBitmap::from_types(&[]))),
        )
        .collect();
    hashed.sort_by(|a, b| a.0.cmp(&b.0));

    let origin_labels: Vec<&[u8]> = origin.labels().collect();
    let flags = if opt_out { OPT_OUT } else { 0 };
    hashed
        .iter()
        .enumerate()
        .map(|(i, (hash, types))| {
            let label = base32hex_encode(hash).to_ascii_lowercase().into_bytes();
            let owner = Name::from_labels(
                std::iter::once(label.as_slice()).chain(origin_labels.iter().copied()),
            )
            .map_err(|_| DnssecError::InvalidZone("NSEC3 owner name too long"))?;
            Ok(Record {
                name: owner,
                rtype: RecordType::Nsec3,
                class: Class::In,
                ttl,
                data: RData::Nsec3(Nsec3 {
                    hash_alg: NSEC3_SHA1,
                    flags,
                    iterations,
                    salt: salt.to_vec(),
                    next_hashed: hashed[(i + 1) % hashed.len()].0.to_vec(),
                    types: types.clone(),
                }),
            })
        })
        .collect()
}
