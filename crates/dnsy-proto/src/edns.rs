//! EDNS(0) (RFC 6891): the OPT pseudo-record, its options, Extended DNS Errors (RFC 8914) and
//! response padding (RFC 7830, RFC 8467).

use crate::{EncodeError, WireError, WireReader, WireWriter};

/// The only EDNS version this implementation understands; others are answered with BADVERS.
pub const EDNS_VERSION: u8 = 0;

/// UDP payload size advertised when DNSY creates an OPT record itself.
pub const DEFAULT_UDP_PAYLOAD: u16 = 1232;

/// Response padding block size recommended for `DoT` and `DoH` (RFC 8467 section 4.1).
pub const PADDING_BLOCK: usize = 468;

const OPT_CLIENT_SUBNET: u16 = 8;
const OPT_COOKIE: u16 = 10;
const OPT_PADDING: u16 = 12;
const OPT_EXTENDED_ERROR: u16 = 15;
const DO_BIT: u32 = 0x8000;

/// Extended DNS Error info codes (RFC 8914) used by DNSY.
pub mod ede {
    pub const UNSUPPORTED_DNSKEY_ALG: u16 = 1;
    pub const UNSUPPORTED_DS_DIGEST: u16 = 2;
    pub const STALE_ANSWER: u16 = 3;
    pub const DNSSEC_INDETERMINATE: u16 = 5;
    pub const DNSSEC_BOGUS: u16 = 6;
    pub const SIGNATURE_EXPIRED: u16 = 7;
    pub const SIGNATURE_NOT_YET_VALID: u16 = 8;
    pub const DNSKEY_MISSING: u16 = 9;
    pub const RRSIGS_MISSING: u16 = 10;
    pub const NSEC_MISSING: u16 = 12;
    pub const BLOCKED: u16 = 15;
    pub const FILTERED: u16 = 17;
    pub const PROHIBITED: u16 = 18;
    pub const STALE_NXDOMAIN: u16 = 19;
    pub const NO_REACHABLE_AUTHORITY: u16 = 22;
    pub const NETWORK_ERROR: u16 = 23;
}

/// One EDNS option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdnsOption {
    /// Padding of this many zero octets.
    Padding(u16),
    /// Client subnet (RFC 7871), raw option data.
    ClientSubnet(Vec<u8>),
    /// DNS cookie (RFC 7873), raw option data.
    Cookie(Vec<u8>),
    /// Extended DNS Error (RFC 8914).
    ExtendedError { code: u16, text: String },
    /// An option without a named variant.
    Unknown { code: u16, data: Vec<u8> },
}

/// The decoded OPT pseudo-record.
///
/// `ext_rcode` holds the upper eight bits of the extended RCODE as read from the wire. The
/// authoritative rcode is `Message::header.rcode`, which merges both parts on decode and is split
/// again on encode (which overwrites `ext_rcode`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edns {
    pub udp_payload: u16,
    pub ext_rcode: u8,
    pub version: u8,
    pub dnssec_ok: bool,
    pub options: Vec<EdnsOption>,
}

impl Default for Edns {
    fn default() -> Self {
        Self {
            udp_payload: DEFAULT_UDP_PAYLOAD,
            ext_rcode: 0,
            version: EDNS_VERSION,
            dnssec_ok: false,
            options: Vec::new(),
        }
    }
}

impl Edns {
    /// Whether the sender asked for padded responses (it included a Padding option).
    pub fn has_padding(&self) -> bool {
        self.options
            .iter()
            .any(|o| matches!(o, EdnsOption::Padding(_)))
    }

    /// Decodes an OPT record from its CLASS, TTL and RDATA.
    pub(crate) fn decode(class: u16, ttl: u32, rdata: &[u8]) -> Result<Self, WireError> {
        let mut r = WireReader::new(rdata);
        let mut options = Vec::new();
        while r.remaining() > 0 {
            let code = r.read_u16()?;
            let len = usize::from(r.read_u16()?);
            let data = r.read_bytes(len)?;
            options.push(match code {
                OPT_PADDING => {
                    EdnsOption::Padding(u16::try_from(len).map_err(|_| WireError::BadRdata)?)
                }
                OPT_CLIENT_SUBNET => EdnsOption::ClientSubnet(data.to_vec()),
                OPT_COOKIE => EdnsOption::Cookie(data.to_vec()),
                OPT_EXTENDED_ERROR => {
                    let (code, text) = data.split_first_chunk::<2>().ok_or(WireError::BadRdata)?;
                    EdnsOption::ExtendedError {
                        code: u16::from_be_bytes(*code),
                        text: String::from_utf8_lossy(text).into_owned(),
                    }
                }
                code => EdnsOption::Unknown {
                    code,
                    data: data.to_vec(),
                },
            });
        }
        let [ext_rcode, version, flags_hi, _] = ttl.to_be_bytes();
        Ok(Self {
            udp_payload: class,
            ext_rcode,
            version,
            dnssec_ok: u32::from(flags_hi) << 8 & DO_BIT != 0,
            options,
        })
    }

    /// Writes the whole OPT record with `ext_rcode` as the upper rcode bits.
    pub(crate) fn encode(&self, ext_rcode: u8, w: &mut WireWriter) -> Result<(), EncodeError> {
        w.write_u8(0); // root owner name
        w.write_u16(41);
        w.write_u16(self.udp_payload);
        let flags = if self.dnssec_ok { DO_BIT } else { 0 };
        w.write_u32(u32::from(ext_rcode) << 24 | u32::from(self.version) << 16 | flags);
        let len_at = w.len();
        w.write_u16(0);
        for option in &self.options {
            let (code, len) = match option {
                EdnsOption::Padding(n) => (OPT_PADDING, usize::from(*n)),
                EdnsOption::ClientSubnet(d) => (OPT_CLIENT_SUBNET, d.len()),
                EdnsOption::Cookie(d) => (OPT_COOKIE, d.len()),
                EdnsOption::ExtendedError { text, .. } => (OPT_EXTENDED_ERROR, 2 + text.len()),
                EdnsOption::Unknown { code, data } => (*code, data.len()),
            };
            w.write_u16(code);
            w.write_u16(u16::try_from(len).map_err(|_| EncodeError::RdataTooLong)?);
            match option {
                EdnsOption::Padding(n) => w.write_bytes(&vec![0; usize::from(*n)]),
                EdnsOption::ClientSubnet(d) | EdnsOption::Cookie(d) => w.write_bytes(d),
                EdnsOption::ExtendedError { code, text } => {
                    w.write_u16(*code);
                    w.write_bytes(text.as_bytes());
                }
                EdnsOption::Unknown { data, .. } => w.write_bytes(data),
            }
        }
        let rdlen = u16::try_from(w.len() - len_at - 2).map_err(|_| EncodeError::RdataTooLong)?;
        w.patch_u16(len_at, rdlen);
        Ok(())
    }
}

#[cfg(test)]
#[path = "edns_tests.rs"]
mod tests;
