//! NSEC/NSEC3 type bitmaps (RFC 4034 4.1.2) and record type mnemonics.

use std::fmt;

use crate::rdata::RdataParseError;
use crate::{RecordType, WireError, WireReader, WireWriter};

/// Octets in one full window block.
const MAX_WINDOW_LEN: usize = 32;

/// A set of record types, encoded on the wire as window blocks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct TypeBitmap {
    /// Sorted, deduplicated type codes.
    types: Vec<u16>,
}

impl TypeBitmap {
    /// Builds a bitmap from any list of types; order and duplicates do not matter.
    pub fn from_types(types: &[RecordType]) -> Self {
        let mut types: Vec<u16> = types.iter().map(|t| u16::from(*t)).collect();
        types.sort_unstable();
        types.dedup();
        Self { types }
    }

    pub fn contains(&self, t: RecordType) -> bool {
        self.types.binary_search(&u16::from(t)).is_ok()
    }

    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// The types in ascending numeric order.
    pub fn types(&self) -> impl Iterator<Item = RecordType> + '_ {
        self.types.iter().map(|t| RecordType::from(*t))
    }

    /// Appends the window blocks.
    pub fn encode(&self, w: &mut WireWriter) {
        let mut i = 0;
        while i < self.types.len() {
            let window = self.types[i] >> 8;
            let mut block = [0u8; MAX_WINDOW_LEN];
            let mut used = 0;
            while i < self.types.len() && self.types[i] >> 8 == window {
                let low = usize::from(self.types[i] & 0xFF);
                block[low / 8] |= 0x80 >> (low % 8);
                used = low / 8 + 1;
                i += 1;
            }
            w.write_u8(u8::try_from(window).unwrap_or(u8::MAX));
            w.write_u8(u8::try_from(used).unwrap_or(u8::MAX));
            w.write_bytes(&block[..used]);
        }
    }

    /// Reads window blocks up to absolute reader position `end`. Rejects what the
    /// presentation format cannot represent: empty or oversized blocks, blocks out of
    /// order or repeated, and blocks with trailing zero octets.
    pub fn decode(r: &mut WireReader<'_>, end: usize) -> Result<Self, WireError> {
        let mut types = Vec::new();
        let mut previous: Option<u8> = None;
        while r.position() < end {
            let window = r.read_u8()?;
            let len = usize::from(r.read_u8()?);
            if len == 0 || len > MAX_WINDOW_LEN || previous.is_some_and(|p| window <= p) {
                return Err(WireError::BadRdata);
            }
            if end.checked_sub(r.position()).is_none_or(|left| left < len) {
                return Err(WireError::BadRdata);
            }
            let block = r.read_bytes(len)?;
            if block[len - 1] == 0 {
                return Err(WireError::BadRdata);
            }
            for (octet, byte) in block.iter().enumerate() {
                for bit in 0..8usize {
                    if byte & (0x80 >> bit) != 0 {
                        let low =
                            u16::try_from(octet * 8 + bit).map_err(|_| WireError::BadRdata)?;
                        types.push(u16::from(window) << 8 | low);
                    }
                }
            }
            previous = Some(window);
        }
        Ok(Self { types })
    }

    /// Parses space-separated mnemonics (`A`, `RRSIG`, `TYPE1234`).
    pub(crate) fn parse<'a>(
        tokens: impl Iterator<Item = &'a str>,
    ) -> Result<Self, RdataParseError> {
        let mut types = Vec::new();
        for t in tokens {
            types.push(type_from_text(t)?);
        }
        Ok(Self::from_types(&types))
    }
}

impl fmt::Display for TypeBitmap {
    /// Space-separated mnemonics, each preceded by a space.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for t in self.types() {
            write!(f, " {}", type_name(t))?;
        }
        Ok(())
    }
}

const MNEMONICS: &[(RecordType, &str)] = &[
    (RecordType::A, "A"),
    (RecordType::Ns, "NS"),
    (RecordType::Cname, "CNAME"),
    (RecordType::Soa, "SOA"),
    (RecordType::Ptr, "PTR"),
    (RecordType::Mx, "MX"),
    (RecordType::Txt, "TXT"),
    (RecordType::Aaaa, "AAAA"),
    (RecordType::Srv, "SRV"),
    (RecordType::Opt, "OPT"),
    (RecordType::Ds, "DS"),
    (RecordType::Rrsig, "RRSIG"),
    (RecordType::Nsec, "NSEC"),
    (RecordType::Dnskey, "DNSKEY"),
    (RecordType::Nsec3, "NSEC3"),
    (RecordType::Nsec3param, "NSEC3PARAM"),
    (RecordType::Cds, "CDS"),
    (RecordType::Cdnskey, "CDNSKEY"),
    (RecordType::Svcb, "SVCB"),
    (RecordType::Https, "HTTPS"),
    (RecordType::Caa, "CAA"),
    (RecordType::Any, "ANY"),
];

/// Mnemonic of a type, or the RFC 3597 `TYPEnnn` form.
pub(crate) fn type_name(t: RecordType) -> String {
    MNEMONICS
        .iter()
        .find(|(known, _)| *known == t)
        .map_or_else(|| format!("TYPE{}", u16::from(t)), |(_, n)| (*n).to_owned())
}

/// Parses a mnemonic or `TYPEnnn`, case-insensitively.
pub(crate) fn type_from_text(s: &str) -> Result<RecordType, RdataParseError> {
    if let Some((t, _)) = MNEMONICS.iter().find(|(_, n)| n.eq_ignore_ascii_case(s)) {
        return Ok(*t);
    }
    let digits = s
        .get(..4)
        .filter(|p| p.eq_ignore_ascii_case("TYPE"))
        .map(|_| &s[4..])
        .filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
        .ok_or(RdataParseError::InvalidField("type"))?;
    digits
        .parse::<u16>()
        .map(RecordType::from)
        .map_err(|_| RdataParseError::InvalidField("type"))
}
