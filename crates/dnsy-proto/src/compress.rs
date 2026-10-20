//! RDATA wire codec and the RDATA name-compression policy.
//!
//! RFC 3597 section 4 limits compression to the RDATA names of the RFC 1035 types, so names in
//! NS, CNAME, PTR, MX and SOA RDATA go through the compression map. Every other type writes its
//! names uncompressed: SRV (RFC 2782) and the DNSSEC types RRSIG and NSEC (RFC 4034 section 6.2)
//! must not be compressed. Decoding accepts pointers anywhere, as RFC 3597 asks of receivers.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::message::{DecodeError, RData, Soa};
use crate::{Name, RecordType, WireReader, WireWriter};

/// Writes a name inside RDATA, compressing it only when the record type allows it.
pub(crate) fn write_rdata_name(w: &mut WireWriter, name: &Name, compress: bool) {
    if compress {
        w.write_name(name);
    } else {
        w.write_bytes(name.as_wire());
    }
}

/// Writes the RDATA of `data` (without the RDLENGTH prefix).
pub(crate) fn write_rdata(w: &mut WireWriter, data: &RData) {
    match data {
        RData::A(ip) => w.write_bytes(&ip.octets()),
        RData::Aaaa(ip) => w.write_bytes(&ip.octets()),
        RData::Ns(name) | RData::Cname(name) | RData::Ptr(name) => {
            write_rdata_name(w, name, true);
        }
        RData::Mx {
            preference,
            exchange,
        } => {
            w.write_u16(*preference);
            write_rdata_name(w, exchange, true);
        }
        RData::Soa(soa) => {
            write_rdata_name(w, &soa.mname, true);
            write_rdata_name(w, &soa.rname, true);
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
            write_rdata_name(w, target, false);
        }
        RData::Opaque { data, .. } => w.write_bytes(data),
    }
}

/// Reads `len` octets of RDATA for `rtype`. The decoded fields must consume exactly `len` octets.
pub(crate) fn read_rdata(
    r: &mut WireReader<'_>,
    rtype: RecordType,
    len: usize,
) -> Result<RData, DecodeError> {
    if r.remaining() < len {
        return Err(crate::WireError::Truncated.into());
    }
    let start = r.position();
    let data = match rtype {
        RecordType::A => RData::A(Ipv4Addr::from(fixed::<4>(r, len)?)),
        RecordType::Aaaa => RData::Aaaa(Ipv6Addr::from(fixed::<16>(r, len)?)),
        RecordType::Ns => RData::Ns(r.read_name()?),
        RecordType::Cname => RData::Cname(r.read_name()?),
        RecordType::Ptr => RData::Ptr(r.read_name()?),
        RecordType::Mx => RData::Mx {
            preference: r.read_u16()?,
            exchange: r.read_name()?,
        },
        RecordType::Soa => RData::Soa(Soa {
            mname: r.read_name()?,
            rname: r.read_name()?,
            serial: r.read_u32()?,
            refresh: r.read_u32()?,
            retry: r.read_u32()?,
            expire: r.read_u32()?,
            minimum: r.read_u32()?,
        }),
        RecordType::Srv => RData::Srv {
            priority: r.read_u16()?,
            weight: r.read_u16()?,
            port: r.read_u16()?,
            target: r.read_name()?,
        },
        other => RData::Opaque {
            rtype: other.into(),
            data: r.read_bytes(len)?.to_vec(),
        },
    };
    if r.position() - start != len {
        return Err(DecodeError::BadRdata);
    }
    Ok(data)
}

fn fixed<const N: usize>(r: &mut WireReader<'_>, len: usize) -> Result<[u8; N], DecodeError> {
    if len != N {
        return Err(DecodeError::BadRdata);
    }
    Ok(r.read_bytes(N)?.try_into().expect("read exactly N octets"))
}
