//! Master-file tokenizer and string escaping shared by the RDATA presentation code.

use std::fmt::{self, Write as _};

use super::RdataParseError;

/// One whitespace-separated token of presentation text.
pub(super) struct Token {
    /// The text as written, escapes intact (what [`crate::Name::from_ascii`] expects).
    pub raw: String,
    /// The text with escapes resolved.
    pub bytes: Vec<u8>,
    pub quoted: bool,
}

impl Token {
    pub fn text(&self, field: &'static str) -> Result<&str, RdataParseError> {
        std::str::from_utf8(&self.bytes).map_err(|_| RdataParseError::InvalidField(field))
    }
}

/// Splits RFC 1035 master-file RDATA into tokens: whitespace separated, `"..."` quoted
/// strings, `\X` and `\DDD` escapes. Parentheses and comments are not supported.
pub(super) fn tokenize(text: &str) -> Result<Vec<Token>, RdataParseError> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }
        let quoted = chars[i] == '"';
        if quoted {
            i += 1;
        }
        let mut raw = String::new();
        let mut bytes = Vec::new();
        let mut closed = !quoted;
        while i < chars.len() {
            let c = chars[i];
            if quoted && c == '"' {
                closed = true;
                i += 1;
                break;
            }
            if !quoted && c.is_whitespace() {
                break;
            }
            if c == '\\' {
                let next = *chars.get(i + 1).ok_or(RdataParseError::BadEscape)?;
                if next.is_ascii_digit() {
                    let digits = chars.get(i + 1..i + 4).ok_or(RdataParseError::BadEscape)?;
                    let value = digits.iter().try_fold(0u32, |acc, d| {
                        d.to_digit(10)
                            .map(|d| acc * 10 + d)
                            .ok_or(RdataParseError::BadEscape)
                    })?;
                    bytes.push(u8::try_from(value).map_err(|_| RdataParseError::BadEscape)?);
                    raw.extend(&chars[i..i + 4]);
                    i += 4;
                } else {
                    push_char(&mut bytes, next)?;
                    raw.push('\\');
                    raw.push(next);
                    i += 2;
                }
            } else {
                push_char(&mut bytes, c)?;
                raw.push(c);
                i += 1;
            }
        }
        if !closed {
            return Err(RdataParseError::UnterminatedQuote);
        }
        tokens.push(Token { raw, bytes, quoted });
    }
    Ok(tokens)
}

fn push_char(bytes: &mut Vec<u8>, c: char) -> Result<(), RdataParseError> {
    if !c.is_ascii() {
        return Err(RdataParseError::InvalidField("non-ASCII character"));
    }
    let mut buf = [0u8; 4];
    bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    Ok(())
}

/// Writes `data` as a quoted character-string.
pub(super) fn write_quoted(f: &mut fmt::Formatter<'_>, data: &[u8]) -> fmt::Result {
    f.write_char('"')?;
    for &b in data {
        match b {
            b'"' | b'\\' => write!(f, "\\{}", char::from(b))?,
            0x20..=0x7e => f.write_char(char::from(b))?,
            _ => write!(f, "\\{b:03}")?,
        }
    }
    f.write_char('"')
}

pub(super) fn write_hex(f: &mut fmt::Formatter<'_>, data: &[u8]) -> fmt::Result {
    for b in data {
        write!(f, "{b:02X}")?;
    }
    Ok(())
}

pub(super) fn parse_hex(text: &str) -> Result<Vec<u8>, RdataParseError> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return Err(RdataParseError::InvalidField("hex"));
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let s = std::str::from_utf8(pair).map_err(|_| RdataParseError::InvalidField("hex"))?;
            u8::from_str_radix(s, 16).map_err(|_| RdataParseError::InvalidField("hex"))
        })
        .collect()
}
