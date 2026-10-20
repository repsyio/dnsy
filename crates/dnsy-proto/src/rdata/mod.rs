//! Resource record data: wire codecs and RFC 1035 presentation format.

mod text;

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{Name, RecordType, WireError, WireReader, WireWriter};
use text::{Token, parse_hex, tokenize, write_hex, write_quoted};

/// Maximum length of one TXT character-string.
const MAX_TXT_CHUNK: usize = 255;

/// SOA RDATA (RFC 1035 3.3.13).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Soa {
    pub mname: Name,
    pub rname: Name,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

/// Record data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ns(Name),
    Cname(Name),
    Ptr(Name),
    Mx {
        preference: u16,
        exchange: Name,
    },
    /// Character-strings, each at most 255 octets on the wire; longer ones are split on encode.
    Txt(Vec<Vec<u8>>),
    Soa(Soa),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name,
    },
    Caa {
        flags: u8,
        tag: String,
        value: Vec<u8>,
    },
    /// Any type without a dedicated variant, kept as RFC 3597 opaque data.
    Opaque {
        rtype: u16,
        data: Vec<u8>,
    },
}

/// Errors parsing RDATA presentation text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdataParseError {
    /// A required field is absent.
    MissingField(&'static str),
    /// Tokens remain after the last field.
    TrailingData,
    /// A field that does not parse.
    InvalidField(&'static str),
    /// A malformed `\` escape.
    BadEscape,
    /// A `"` without its closing quote.
    UnterminatedQuote,
}

impl fmt::Display for RdataParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(n) => write!(f, "missing field: {n}"),
            Self::TrailingData => f.write_str("unexpected trailing data"),
            Self::InvalidField(n) => write!(f, "invalid field: {n}"),
            Self::BadEscape => f.write_str("malformed escape"),
            Self::UnterminatedQuote => f.write_str("unterminated quoted string"),
        }
    }
}

impl std::error::Error for RdataParseError {}

impl RData {
    /// The record type of this data.
    pub fn rtype(&self) -> RecordType {
        match self {
            Self::A(_) => RecordType::A,
            Self::Aaaa(_) => RecordType::Aaaa,
            Self::Ns(_) => RecordType::Ns,
            Self::Cname(_) => RecordType::Cname,
            Self::Ptr(_) => RecordType::Ptr,
            Self::Mx { .. } => RecordType::Mx,
            Self::Txt(_) => RecordType::Txt,
            Self::Soa(_) => RecordType::Soa,
            Self::Srv { .. } => RecordType::Srv,
            Self::Caa { .. } => RecordType::Caa,
            Self::Opaque { rtype, .. } => RecordType::from(*rtype),
        }
    }

    /// Reads `rdlen` octets of RDATA of type `rtype`. Names may be compressed. Types
    /// without a variant become [`RData::Opaque`].
    pub fn decode(
        rtype: RecordType,
        r: &mut WireReader<'_>,
        rdlen: usize,
    ) -> Result<Self, WireError> {
        if r.remaining() < rdlen {
            return Err(WireError::Truncated);
        }
        let end = r.position() + rdlen;
        let data = match rtype {
            RecordType::A => {
                let b = r.read_bytes(4)?;
                Self::A(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            }
            RecordType::Aaaa => {
                let b: [u8; 16] = r
                    .read_bytes(16)?
                    .try_into()
                    .map_err(|_| WireError::Truncated)?;
                Self::Aaaa(Ipv6Addr::from(b))
            }
            RecordType::Ns => Self::Ns(r.read_name()?),
            RecordType::Cname => Self::Cname(r.read_name()?),
            RecordType::Ptr => Self::Ptr(r.read_name()?),
            RecordType::Mx => Self::Mx {
                preference: r.read_u16()?,
                exchange: r.read_name()?,
            },
            RecordType::Txt => {
                let mut strings = Vec::new();
                while r.position() < end {
                    let len = usize::from(r.read_u8()?);
                    strings.push(r.read_bytes(len)?.to_vec());
                }
                if strings.is_empty() {
                    return Err(WireError::BadRdata);
                }
                Self::Txt(strings)
            }
            RecordType::Soa => Self::Soa(Soa {
                mname: r.read_name()?,
                rname: r.read_name()?,
                serial: r.read_u32()?,
                refresh: r.read_u32()?,
                retry: r.read_u32()?,
                expire: r.read_u32()?,
                minimum: r.read_u32()?,
            }),
            RecordType::Srv => Self::Srv {
                priority: r.read_u16()?,
                weight: r.read_u16()?,
                port: r.read_u16()?,
                target: r.read_name()?,
            },
            RecordType::Caa => {
                let flags = r.read_u8()?;
                let tag_len = usize::from(r.read_u8()?);
                let tag = String::from_utf8(r.read_bytes(tag_len)?.to_vec())
                    .map_err(|_| WireError::BadRdata)?;
                let value_len = end.checked_sub(r.position()).ok_or(WireError::BadRdata)?;
                Self::Caa {
                    flags,
                    tag,
                    value: r.read_bytes(value_len)?.to_vec(),
                }
            }
            other => Self::Opaque {
                rtype: other.into(),
                data: r.read_bytes(rdlen)?.to_vec(),
            },
        };
        if r.position() == end {
            Ok(data)
        } else {
            Err(WireError::BadRdata)
        }
    }

    /// Appends the RDATA (without RDLENGTH). Names of NS, CNAME, PTR, MX and SOA are
    /// compressed; all others are written in full (RFC 3597, RFC 2782).
    pub fn encode(&self, w: &mut WireWriter) -> Result<(), WireError> {
        match self {
            Self::A(ip) => w.write_bytes(&ip.octets()),
            Self::Aaaa(ip) => w.write_bytes(&ip.octets()),
            Self::Ns(n) | Self::Cname(n) | Self::Ptr(n) => w.write_name(n),
            Self::Mx {
                preference,
                exchange,
            } => {
                w.write_u16(*preference);
                w.write_name(exchange);
            }
            Self::Txt(strings) => {
                if strings.is_empty() {
                    w.write_u8(0);
                }
                for s in strings {
                    if s.is_empty() {
                        w.write_u8(0);
                    }
                    for chunk in s.chunks(MAX_TXT_CHUNK) {
                        w.write_u8(u8::try_from(chunk.len()).map_err(|_| WireError::BadRdata)?);
                        w.write_bytes(chunk);
                    }
                }
            }
            Self::Soa(soa) => {
                w.write_name(&soa.mname);
                w.write_name(&soa.rname);
                for v in [soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum] {
                    w.write_u32(v);
                }
            }
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                w.write_u16(*priority);
                w.write_u16(*weight);
                w.write_u16(*port);
                w.write_bytes(target.as_wire());
            }
            Self::Caa { flags, tag, value } => {
                w.write_u8(*flags);
                w.write_u8(u8::try_from(tag.len()).map_err(|_| WireError::BadRdata)?);
                w.write_bytes(tag.as_bytes());
                w.write_bytes(value);
            }
            Self::Opaque { data, .. } => w.write_bytes(data),
        }
        Ok(())
    }

    /// Parses RFC 1035 presentation text for `rtype`. The RFC 3597 form `\# len hex` is
    /// accepted for every type.
    pub fn parse(rtype: RecordType, text: &str) -> Result<Self, RdataParseError> {
        let tokens = tokenize(text)?;
        if tokens.first().is_some_and(|t| !t.quoted && t.raw == "\\#") {
            return parse_generic(rtype, &tokens[1..]);
        }
        let mut it = tokens.iter();
        let data = match rtype {
            RecordType::A => Self::A(
                next(&mut it, "address")?
                    .text("address")?
                    .parse()
                    .map_err(|_| RdataParseError::InvalidField("address"))?,
            ),
            RecordType::Aaaa => Self::Aaaa(
                next(&mut it, "address")?
                    .text("address")?
                    .parse()
                    .map_err(|_| RdataParseError::InvalidField("address"))?,
            ),
            RecordType::Ns => Self::Ns(name(&mut it, "name")?),
            RecordType::Cname => Self::Cname(name(&mut it, "name")?),
            RecordType::Ptr => Self::Ptr(name(&mut it, "name")?),
            RecordType::Mx => Self::Mx {
                preference: number(&mut it, "preference")?,
                exchange: name(&mut it, "exchange")?,
            },
            RecordType::Txt => {
                let strings: Vec<Vec<u8>> = it.by_ref().map(|t| t.bytes.clone()).collect();
                if strings.is_empty() {
                    return Err(RdataParseError::MissingField("string"));
                }
                Self::Txt(strings)
            }
            RecordType::Soa => Self::Soa(Soa {
                mname: name(&mut it, "mname")?,
                rname: name(&mut it, "rname")?,
                serial: number(&mut it, "serial")?,
                refresh: number(&mut it, "refresh")?,
                retry: number(&mut it, "retry")?,
                expire: number(&mut it, "expire")?,
                minimum: number(&mut it, "minimum")?,
            }),
            RecordType::Srv => Self::Srv {
                priority: number(&mut it, "priority")?,
                weight: number(&mut it, "weight")?,
                port: number(&mut it, "port")?,
                target: name(&mut it, "target")?,
            },
            RecordType::Caa => {
                let flags = number(&mut it, "flags")?;
                let tag = next(&mut it, "tag")?.text("tag")?.to_owned();
                if tag.is_empty() || !tag.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    return Err(RdataParseError::InvalidField("tag"));
                }
                let value = next(&mut it, "value")?.bytes.clone();
                Self::Caa { flags, tag, value }
            }
            other => {
                return Err(RdataParseError::InvalidField(
                    if matches!(other, RecordType::Opt | RecordType::Any) {
                        "type has no presentation form"
                    } else {
                        "type requires the \\# form"
                    },
                ));
            }
        };
        if it.next().is_some() {
            return Err(RdataParseError::TrailingData);
        }
        Ok(data)
    }
}

fn next<'a>(
    it: &mut std::slice::Iter<'a, Token>,
    field: &'static str,
) -> Result<&'a Token, RdataParseError> {
    it.next().ok_or(RdataParseError::MissingField(field))
}

fn name(
    it: &mut std::slice::Iter<'_, Token>,
    field: &'static str,
) -> Result<Name, RdataParseError> {
    Name::from_ascii(&next(it, field)?.raw).map_err(|_| RdataParseError::InvalidField(field))
}

fn number<T: std::str::FromStr>(
    it: &mut std::slice::Iter<'_, Token>,
    field: &'static str,
) -> Result<T, RdataParseError> {
    next(it, field)?
        .text(field)?
        .parse()
        .map_err(|_| RdataParseError::InvalidField(field))
}

/// RFC 3597 `\# <len> <hex>`; `tokens` excludes the `\#`.
fn parse_generic(rtype: RecordType, tokens: &[Token]) -> Result<RData, RdataParseError> {
    let mut it = tokens.iter();
    let len: usize = number(&mut it, "length")?;
    let hex: String = it.map(|t| t.raw.as_str()).collect();
    let data = parse_hex(&hex)?;
    if data.len() != len {
        return Err(RdataParseError::InvalidField("length"));
    }
    let mut reader = WireReader::new(&data);
    RData::decode(rtype, &mut reader, len).map_err(|_| RdataParseError::InvalidField("rdata"))
}

impl fmt::Display for RData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A(ip) => write!(f, "{ip}"),
            Self::Aaaa(ip) => write!(f, "{ip}"),
            Self::Ns(n) | Self::Cname(n) | Self::Ptr(n) => write!(f, "{n}"),
            Self::Mx {
                preference,
                exchange,
            } => write!(f, "{preference} {exchange}"),
            Self::Txt(strings) => {
                for (i, s) in strings.iter().enumerate() {
                    if i > 0 {
                        f.write_str(" ")?;
                    }
                    write_quoted(f, s)?;
                }
                Ok(())
            }
            Self::Soa(s) => write!(
                f,
                "{} {} {} {} {} {} {}",
                s.mname, s.rname, s.serial, s.refresh, s.retry, s.expire, s.minimum
            ),
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => write!(f, "{priority} {weight} {port} {target}"),
            Self::Caa { flags, tag, value } => {
                write!(f, "{flags} {tag} ")?;
                write_quoted(f, value)
            }
            Self::Opaque { data, .. } => {
                write!(f, "\\# {}", data.len())?;
                if !data.is_empty() {
                    f.write_str(" ")?;
                    write_hex(f, data)?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests;
