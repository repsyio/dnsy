//! Base64 (RFC 4648 4) and unpadded base32hex (RFC 4648 7, RFC 5155 3.3).

use std::fmt::{self, Write as _};

use crate::rdata::RdataParseError;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B32HEX: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

pub(super) fn write_base64(f: &mut fmt::Formatter<'_>, data: &[u8]) -> fmt::Result {
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                f.write_char(char::from(B64[(n >> (18 - 6 * i) & 63) as usize]))?;
            } else {
                f.write_char('=')?;
            }
        }
    }
    Ok(())
}

pub(super) fn parse_base64(text: &str) -> Result<Vec<u8>, RdataParseError> {
    const ERR: RdataParseError = RdataParseError::InvalidField("base64");
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return Err(ERR);
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let quads = bytes.len() / 4;
    for (q, quad) in bytes.chunks(4).enumerate() {
        let pad = quad.iter().rev().take_while(|b| **b == b'=').count();
        if pad > 2 || (pad > 0 && q + 1 != quads) {
            return Err(ERR);
        }
        let mut n = 0u32;
        for b in &quad[..4 - pad] {
            let v = B64.iter().position(|c| c == b).ok_or(ERR)?;
            n = n << 6 | u32::try_from(v).map_err(|_| ERR)?;
        }
        n <<= 6 * pad;
        for i in 0..3 - pad {
            out.push(u8::try_from(n >> (16 - 8 * i) & 0xFF).map_err(|_| ERR)?);
        }
    }
    Ok(out)
}

/// Uppercase unpadded base32hex.
pub fn base32hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in data {
        acc = acc << 8 | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32HEX[(acc >> bits & 31) as usize]));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(B32HEX[(acc << (5 - bits) & 31) as usize]));
    }
    out
}

/// Decodes unpadded base32hex, case-insensitively. Rejects the empty string, impossible
/// lengths and non-zero trailing bits, so `encode(decode(s))` equals `s` uppercased.
pub fn base32hex_decode(text: &str) -> Result<Vec<u8>, RdataParseError> {
    const ERR: RdataParseError = RdataParseError::InvalidField("base32hex");
    if text.is_empty() || matches!(text.len() % 8, 1 | 3 | 6) {
        return Err(ERR);
    }
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let v = B32HEX
            .iter()
            .position(|x| *x == c.to_ascii_uppercase())
            .ok_or(ERR)?;
        acc = acc << 5 | u32::try_from(v).map_err(|_| ERR)?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(acc >> bits & 0xFF).map_err(|_| ERR)?);
            acc &= (1 << bits) - 1;
        }
    }
    if acc != 0 {
        return Err(ERR);
    }
    Ok(out)
}
