//! DNSSEC RDATA: DNSKEY/CDNSKEY, RRSIG, DS/CDS, NSEC, NSEC3, NSEC3PARAM
//! (RFC 4034, RFC 5155, RFC 8078).
//!
//! Wire decoding rejects what the presentation format cannot represent (empty keys,
//! signatures, digests and hashes; malformed type bitmaps), so that
//! `parse(display(x)) == x` holds for every decoded value. Algorithm numbers are
//! numeric in presentation text; names inside these RDATA are never compressed on
//! encode.

mod encoding;
mod time;

use std::fmt;

use super::text::{Token, parse_hex, write_hex};
use super::{RdataParseError, name, next, number};
use crate::bitmap::{TypeBitmap, type_from_text, type_name};
use crate::{Name, RecordType, WireError, WireReader, WireWriter};
use encoding::{parse_base64, write_base64};

pub use encoding::{base32hex_decode, base32hex_encode};
pub use time::{format_timestamp, parse_timestamp, serial_gt, serial_lt};

/// Octets left between the reader and absolute position `end`.
fn rest(r: &mut WireReader<'_>, end: usize) -> Result<Vec<u8>, WireError> {
    let len = end.checked_sub(r.position()).ok_or(WireError::BadRdata)?;
    let bytes = r.read_bytes(len)?.to_vec();
    if bytes.is_empty() {
        return Err(WireError::BadRdata);
    }
    Ok(bytes)
}

/// Remaining tokens joined (base64 and hex may be split over several tokens).
fn joined(
    it: &mut std::slice::Iter<'_, Token>,
    field: &'static str,
) -> Result<String, RdataParseError> {
    let s: String = it.by_ref().map(|t| t.raw.as_str()).collect();
    if s.is_empty() {
        Err(RdataParseError::MissingField(field))
    } else {
        Ok(s)
    }
}

/// DNSKEY and CDNSKEY RDATA (RFC 4034 2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dnskey {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

impl Dnskey {
    /// Key tag per RFC 4034 Appendix B. Algorithm 1 (RSA/MD5) uses the special case of
    /// the third and second last key octets; a key too short for it yields 0.
    pub fn key_tag(&self) -> u16 {
        if self.algorithm == 1 {
            return match self.public_key.as_slice() {
                [.., hi, lo, _] => u16::from_be_bytes([*hi, *lo]),
                _ => 0,
            };
        }
        let mut w = WireWriter::new();
        self.encode(&mut w);
        let sum = w.finish().iter().enumerate().fold(0u64, |acc, (i, b)| {
            acc + if i % 2 == 0 {
                u64::from(*b) << 8
            } else {
                u64::from(*b)
            }
        });
        let sum = sum + (sum >> 16 & 0xFFFF);
        u16::try_from(sum & 0xFFFF).unwrap_or_default()
    }

    /// The zone key flag (bit 7).
    pub fn is_zone_key(&self) -> bool {
        self.flags & 0x0100 != 0
    }

    /// The secure entry point flag (bit 15).
    pub fn is_sep(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    pub(crate) fn encode(&self, w: &mut WireWriter) {
        w.write_u16(self.flags);
        w.write_u8(self.protocol);
        w.write_u8(self.algorithm);
        w.write_bytes(&self.public_key);
    }

    pub(crate) fn decode(r: &mut WireReader<'_>, end: usize) -> Result<Self, WireError> {
        Ok(Self {
            flags: r.read_u16()?,
            protocol: r.read_u8()?,
            algorithm: r.read_u8()?,
            public_key: rest(r, end)?,
        })
    }

    pub(in crate::rdata) fn parse(
        it: &mut std::slice::Iter<'_, Token>,
    ) -> Result<Self, RdataParseError> {
        Ok(Self {
            flags: number(it, "flags")?,
            protocol: number(it, "protocol")?,
            algorithm: number(it, "algorithm")?,
            public_key: parse_base64(&joined(it, "public key")?)?,
        })
    }
}

impl fmt::Display for Dnskey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} ", self.flags, self.protocol, self.algorithm)?;
        write_base64(f, &self.public_key)
    }
}

/// RRSIG RDATA (RFC 4034 3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rrsig {
    pub type_covered: RecordType,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub expiration: u32,
    pub inception: u32,
    pub key_tag: u16,
    pub signer: Name,
    pub signature: Vec<u8>,
}

impl Rrsig {
    /// True when `now` lies within `[inception, expiration]` under RFC 1982 serial
    /// arithmetic.
    pub fn is_current(&self, now: u32) -> bool {
        let le = |a: u32, b: u32| a == b || serial_lt(a, b);
        le(self.inception, now) && le(now, self.expiration)
    }

    /// The RDATA up to, not including, the signature (RFC 4034 3.1.8.1), with the
    /// signer name written lowercased.
    pub(crate) fn signed_prefix(&self) -> Vec<u8> {
        let mut w = WireWriter::new();
        w.write_u16(self.type_covered.into());
        w.write_u8(self.algorithm);
        w.write_u8(self.labels);
        w.write_u32(self.original_ttl);
        w.write_u32(self.expiration);
        w.write_u32(self.inception);
        w.write_u16(self.key_tag);
        w.write_bytes(self.signer.to_lowercase().as_wire());
        w.finish()
    }

    pub(crate) fn encode(&self, w: &mut WireWriter) {
        w.write_u16(self.type_covered.into());
        w.write_u8(self.algorithm);
        w.write_u8(self.labels);
        w.write_u32(self.original_ttl);
        w.write_u32(self.expiration);
        w.write_u32(self.inception);
        w.write_u16(self.key_tag);
        w.write_bytes(self.signer.as_wire());
        w.write_bytes(&self.signature);
    }

    pub(crate) fn decode(r: &mut WireReader<'_>, end: usize) -> Result<Self, WireError> {
        Ok(Self {
            type_covered: r.read_u16()?.into(),
            algorithm: r.read_u8()?,
            labels: r.read_u8()?,
            original_ttl: r.read_u32()?,
            expiration: r.read_u32()?,
            inception: r.read_u32()?,
            key_tag: r.read_u16()?,
            signer: r.read_name()?,
            signature: rest(r, end)?,
        })
    }

    pub(in crate::rdata) fn parse(
        it: &mut std::slice::Iter<'_, Token>,
    ) -> Result<Self, RdataParseError> {
        let type_covered = type_from_text(&next(it, "type covered")?.raw)?;
        let algorithm = number(it, "algorithm")?;
        let labels = number(it, "labels")?;
        let original_ttl = number(it, "original ttl")?;
        let expiration = timestamp(it, "expiration")?;
        let inception = timestamp(it, "inception")?;
        Ok(Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag: number(it, "key tag")?,
            signer: name(it, "signer")?,
            signature: parse_base64(&joined(it, "signature")?)?,
        })
    }
}

fn timestamp(
    it: &mut std::slice::Iter<'_, Token>,
    field: &'static str,
) -> Result<u32, RdataParseError> {
    parse_timestamp(&next(it, field)?.raw).ok_or(RdataParseError::InvalidField(field))
}

impl fmt::Display for Rrsig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {} {} ",
            type_name(self.type_covered),
            self.algorithm,
            self.labels,
            self.original_ttl,
            format_timestamp(self.expiration),
            format_timestamp(self.inception),
            self.key_tag,
            self.signer
        )?;
        write_base64(f, &self.signature)
    }
}

/// DS and CDS RDATA (RFC 4034 5, RFC 8078).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ds {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

impl Ds {
    pub(crate) fn encode(&self, w: &mut WireWriter) {
        w.write_u16(self.key_tag);
        w.write_u8(self.algorithm);
        w.write_u8(self.digest_type);
        w.write_bytes(&self.digest);
    }

    pub(crate) fn decode(r: &mut WireReader<'_>, end: usize) -> Result<Self, WireError> {
        Ok(Self {
            key_tag: r.read_u16()?,
            algorithm: r.read_u8()?,
            digest_type: r.read_u8()?,
            digest: rest(r, end)?,
        })
    }

    pub(in crate::rdata) fn parse(
        it: &mut std::slice::Iter<'_, Token>,
    ) -> Result<Self, RdataParseError> {
        Ok(Self {
            key_tag: number(it, "key tag")?,
            algorithm: number(it, "algorithm")?,
            digest_type: number(it, "digest type")?,
            digest: parse_hex(&joined(it, "digest")?)?,
        })
    }
}

impl fmt::Display for Ds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} ",
            self.key_tag, self.algorithm, self.digest_type
        )?;
        write_hex(f, &self.digest)
    }
}

/// NSEC3 RDATA (RFC 5155 3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nsec3 {
    pub hash_alg: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
    pub next_hashed: Vec<u8>,
    pub types: TypeBitmap,
}

/// NSEC3PARAM RDATA (RFC 5155 4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nsec3Param {
    pub hash_alg: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
}

fn write_salt(f: &mut fmt::Formatter<'_>, salt: &[u8]) -> fmt::Result {
    if salt.is_empty() {
        f.write_str("-")
    } else {
        write_hex(f, salt)
    }
}

fn parse_salt(it: &mut std::slice::Iter<'_, Token>) -> Result<Vec<u8>, RdataParseError> {
    let raw = &next(it, "salt")?.raw;
    let salt = if raw == "-" {
        Vec::new()
    } else {
        parse_hex(raw)?
    };
    if salt.len() > usize::from(u8::MAX) {
        return Err(RdataParseError::InvalidField("salt"));
    }
    Ok(salt)
}

/// Writes a one-octet length followed by `data`.
fn write_prefixed(w: &mut WireWriter, data: &[u8]) -> Result<(), WireError> {
    w.write_u8(u8::try_from(data.len()).map_err(|_| WireError::BadRdata)?);
    w.write_bytes(data);
    Ok(())
}

fn read_prefixed(r: &mut WireReader<'_>) -> Result<Vec<u8>, WireError> {
    let len = usize::from(r.read_u8()?);
    Ok(r.read_bytes(len)?.to_vec())
}

impl Nsec3 {
    pub(crate) fn encode(&self, w: &mut WireWriter) -> Result<(), WireError> {
        w.write_u8(self.hash_alg);
        w.write_u8(self.flags);
        w.write_u16(self.iterations);
        write_prefixed(w, &self.salt)?;
        if self.next_hashed.is_empty() {
            return Err(WireError::BadRdata);
        }
        write_prefixed(w, &self.next_hashed)?;
        self.types.encode(w);
        Ok(())
    }

    pub(crate) fn decode(r: &mut WireReader<'_>, end: usize) -> Result<Self, WireError> {
        let hash_alg = r.read_u8()?;
        let flags = r.read_u8()?;
        let iterations = r.read_u16()?;
        let salt = read_prefixed(r)?;
        let next_hashed = read_prefixed(r)?;
        if next_hashed.is_empty() {
            return Err(WireError::BadRdata);
        }
        Ok(Self {
            hash_alg,
            flags,
            iterations,
            salt,
            next_hashed,
            types: TypeBitmap::decode(r, end)?,
        })
    }

    pub(in crate::rdata) fn parse(
        it: &mut std::slice::Iter<'_, Token>,
    ) -> Result<Self, RdataParseError> {
        Ok(Self {
            hash_alg: number(it, "hash algorithm")?,
            flags: number(it, "flags")?,
            iterations: number(it, "iterations")?,
            salt: parse_salt(it)?,
            next_hashed: base32hex_decode(&next(it, "next hashed owner")?.raw)?,
            types: TypeBitmap::parse(it.map(|t| t.raw.as_str()))?,
        })
    }
}

impl fmt::Display for Nsec3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} ", self.hash_alg, self.flags, self.iterations)?;
        write_salt(f, &self.salt)?;
        write!(f, " {}{}", base32hex_encode(&self.next_hashed), self.types)
    }
}

impl Nsec3Param {
    pub(crate) fn encode(&self, w: &mut WireWriter) -> Result<(), WireError> {
        w.write_u8(self.hash_alg);
        w.write_u8(self.flags);
        w.write_u16(self.iterations);
        write_prefixed(w, &self.salt)
    }

    pub(crate) fn decode(r: &mut WireReader<'_>) -> Result<Self, WireError> {
        Ok(Self {
            hash_alg: r.read_u8()?,
            flags: r.read_u8()?,
            iterations: r.read_u16()?,
            salt: read_prefixed(r)?,
        })
    }

    pub(in crate::rdata) fn parse(
        it: &mut std::slice::Iter<'_, Token>,
    ) -> Result<Self, RdataParseError> {
        Ok(Self {
            hash_alg: number(it, "hash algorithm")?,
            flags: number(it, "flags")?,
            iterations: number(it, "iterations")?,
            salt: parse_salt(it)?,
        })
    }
}

impl fmt::Display for Nsec3Param {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} ", self.hash_alg, self.flags, self.iterations)?;
        write_salt(f, &self.salt)
    }
}

/// NSEC wire form: next name (uncompressed) and type bitmap.
pub(crate) fn encode_nsec(w: &mut WireWriter, next: &Name, types: &TypeBitmap) {
    w.write_bytes(next.as_wire());
    types.encode(w);
}

pub(crate) fn decode_nsec(
    r: &mut WireReader<'_>,
    end: usize,
) -> Result<(Name, TypeBitmap), WireError> {
    Ok((r.read_name()?, TypeBitmap::decode(r, end)?))
}

pub(in crate::rdata) fn parse_nsec(
    it: &mut std::slice::Iter<'_, Token>,
) -> Result<(Name, TypeBitmap), RdataParseError> {
    Ok((
        name(it, "next domain name")?,
        TypeBitmap::parse(it.map(|t| t.raw.as_str()))?,
    ))
}

#[cfg(test)]
mod tests;
