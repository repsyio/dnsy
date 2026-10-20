//! Blocklist line parsers: hosts files, plain domain lists and an adblock subset.
//!
//! Parsing is total: a malformed line is counted, never fatal, and never panics. Lines are read
//! with a hard length cap so a hostile list cannot force an unbounded allocation.

use std::io::{self, BufRead, Read};
use std::net::IpAddr;

/// Longest line (bytes, excluding the terminator) that is parsed; longer lines count as invalid.
pub const MAX_LINE_LEN: usize = 2048;

/// Longest domain text accepted (the presentation form of a 255-octet wire name).
const MAX_DOMAIN_LEN: usize = 253;

/// Host names that appear in hosts files but are not blocking targets.
const HOSTS_SKIP: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "0.0.0.0",
];

/// The syntax of a list source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListFormat {
    /// `0.0.0.0 example.com` (any IP address, one or more names per line).
    Hosts,
    /// One domain per line; `*.example.com` is the same as `example.com`.
    Domains,
    /// Adblock subset: `||example.com^` blocks, `@@||example.com^` allows, `!` comments.
    Adblock,
    /// Detect the syntax line by line.
    Auto,
}

/// What a source contained.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ParseStats {
    /// Block entries read (duplicates included).
    pub blocks: usize,
    /// Allow entries read (adblock `@@||`).
    pub allows: usize,
    /// Lines that could not be parsed.
    pub invalid: usize,
    /// Blank lines, comments and ignorable hosts entries.
    pub skipped: usize,
}

/// One parsed entry.
pub(crate) struct Entry<'a> {
    pub domain: &'a str,
    pub allow: bool,
}

/// Why reading a source stopped.
#[derive(Debug)]
pub(crate) enum ReadStop {
    Io(io::Error),
    TooLarge,
}

/// Reads `reader` line by line (bounded), calling `on_line` with each line (invalid UTF-8 and
/// over-long lines are passed as `None`). Stops with `TooLarge` after `max_bytes` of input.
pub(crate) fn for_each_line<R: BufRead>(
    mut reader: R,
    max_bytes: u64,
    mut on_line: impl FnMut(Option<&str>) -> bool,
) -> Result<(), ReadStop> {
    let mut buf = Vec::with_capacity(256);
    let mut total: u64 = 0;
    let mut first = true;
    loop {
        buf.clear();
        let cap = u64::try_from(MAX_LINE_LEN).unwrap_or(u64::MAX) + 2;
        let n = (&mut reader)
            .take(cap)
            .read_until(b'\n', &mut buf)
            .map_err(ReadStop::Io)?;
        if n == 0 {
            return Ok(());
        }
        total += n as u64;
        let mut too_long = false;
        if buf.last() != Some(&b'\n') && n as u64 == cap {
            too_long = true;
            total += discard_line(&mut reader).map_err(ReadStop::Io)?;
        }
        if total > max_bytes {
            return Err(ReadStop::TooLarge);
        }
        let mut line: &[u8] = &buf;
        if first {
            line = line.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(line);
            first = false;
        }
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let text = if too_long || line.len() > MAX_LINE_LEN {
            None
        } else {
            std::str::from_utf8(line).ok()
        };
        if !on_line(text) {
            return Ok(());
        }
    }
}

/// Consumes the rest of the current line, returning the bytes dropped.
fn discard_line<R: BufRead>(reader: &mut R) -> io::Result<u64> {
    let mut dropped = 0u64;
    loop {
        let (done, used) = {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                return Ok(dropped);
            }
            match available.iter().position(|&b| b == b'\n') {
                Some(i) => (true, i + 1),
                None => (false, available.len()),
            }
        };
        reader.consume(used);
        dropped += used as u64;
        if done {
            return Ok(dropped);
        }
    }
}

/// Outcome of parsing one line.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LineKind {
    Skipped,
    Invalid,
    Parsed,
}

/// Parses one line, calling `emit` for each entry found.
pub(crate) fn parse_line<'a>(
    line: &'a str,
    format: ListFormat,
    emit: &mut impl FnMut(Entry<'a>),
) -> LineKind {
    let line = line.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('#') || line.starts_with('[') {
        return LineKind::Skipped;
    }
    let format = match format {
        ListFormat::Auto => {
            if line.starts_with("||") || line.starts_with("@@") {
                ListFormat::Adblock
            } else if line.contains(char::is_whitespace) {
                ListFormat::Hosts
            } else {
                ListFormat::Domains
            }
        }
        other => other,
    };
    match format {
        ListFormat::Hosts => parse_hosts(line, emit),
        ListFormat::Domains => parse_domain(strip_comment(line), emit),
        ListFormat::Adblock | ListFormat::Auto => parse_adblock(line, emit),
    }
}

fn strip_comment(line: &str) -> &str {
    line.split_once('#').map_or(line, |(head, _)| head).trim()
}

fn parse_hosts<'a>(line: &'a str, emit: &mut impl FnMut(Entry<'a>)) -> LineKind {
    let mut tokens = strip_comment(line).split_whitespace();
    let Some(ip) = tokens.next() else {
        return LineKind::Skipped;
    };
    if ip.parse::<IpAddr>().is_err() {
        return LineKind::Invalid;
    }
    let names: Vec<&str> = tokens.collect();
    if names.is_empty() {
        return LineKind::Invalid;
    }
    // Validate every name first so a half-valid line adds nothing.
    let mut valid = Vec::with_capacity(names.len());
    for name in names {
        if HOSTS_SKIP.iter().any(|s| name.eq_ignore_ascii_case(s)) {
            continue;
        }
        match normalize(name) {
            Some(d) => valid.push(d),
            None => return LineKind::Invalid,
        }
    }
    if valid.is_empty() {
        return LineKind::Skipped;
    }
    for domain in valid {
        emit(Entry {
            domain,
            allow: false,
        });
    }
    LineKind::Parsed
}

fn parse_domain<'a>(text: &'a str, emit: &mut impl FnMut(Entry<'a>)) -> LineKind {
    if text.is_empty() {
        return LineKind::Skipped;
    }
    match normalize(text) {
        Some(domain) => {
            emit(Entry {
                domain,
                allow: false,
            });
            LineKind::Parsed
        }
        None => LineKind::Invalid,
    }
}

fn parse_adblock<'a>(line: &'a str, emit: &mut impl FnMut(Entry<'a>)) -> LineKind {
    let (allow, rest) = match line.strip_prefix("@@") {
        Some(r) => (true, r),
        None => (false, line),
    };
    let Some(rest) = rest.strip_prefix("||") else {
        return LineKind::Invalid;
    };
    let Some(domain) = rest.strip_suffix('^') else {
        return LineKind::Invalid;
    };
    match normalize(domain) {
        Some(domain) => {
            emit(Entry { domain, allow });
            LineKind::Parsed
        }
        None => LineKind::Invalid,
    }
}

/// Validates a host name: ASCII (IDN must already be punycode), LDH plus `_`, labels of 1..=63,
/// not an IP address. A leading `*.` is dropped (suffix matching covers it).
pub(crate) fn normalize(text: &str) -> Option<&str> {
    let text = text.strip_prefix("*.").unwrap_or(text);
    let text = text.strip_suffix('.').unwrap_or(text);
    if text.is_empty() || text.len() > MAX_DOMAIN_LEN {
        return None;
    }
    for label in text.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
    }
    // An all-numeric last label means an IP address or garbage, never a registrable name.
    let last = text.rsplit('.').next()?;
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(text)
}
