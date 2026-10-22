use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::NameError;

const MAX_LABEL: usize = 63;
const MAX_WIRE: usize = 255;

/// A domain name stored in uncompressed wire form (length-prefixed labels, ending in the root).
///
/// Equality and hashing are ASCII case-insensitive; ordering is the RFC 4034 6.1 canonical order.
#[derive(Clone)]
pub struct Name {
    wire: WireBuf,
}

/// Names up to this many wire octets (most real ones) live inline, without a heap allocation.
const INLINE: usize = 32;

/// Wire octets: inline up to [`INLINE`], shared beyond, so cloning a long name (an NSEC3 owner,
/// copied into a key, a record and a signature) costs a reference count, not an allocation.
#[derive(Clone)]
enum WireBuf {
    Inline { len: u8, buf: [u8; INLINE] },
    Heap(Arc<[u8]>),
}

impl WireBuf {
    fn new(bytes: &[u8]) -> WireBuf {
        match u8::try_from(bytes.len()) {
            Ok(len) if bytes.len() <= INLINE => {
                let mut buf = [0; INLINE];
                buf[..bytes.len()].copy_from_slice(bytes);
                WireBuf::Inline { len, buf }
            }
            _ => WireBuf::Heap(bytes.into()),
        }
    }
}

impl std::ops::Deref for WireBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            WireBuf::Inline { len, buf } => &buf[..usize::from(*len)],
            WireBuf::Heap(b) => b,
        }
    }
}

/// Iterator over the labels of a [`Name`], leftmost first, excluding the root.
#[derive(Clone)]
pub struct Labels<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(*self.rest.first()?);
        if len == 0 {
            return None;
        }
        let (label, rest) = self.rest[1..].split_at(len);
        self.rest = rest;
        Some(label)
    }
}

impl Name {
    /// The root name `.`.
    pub fn root() -> Name {
        Name::from_wire_unchecked(&[0])
    }

    /// Builds a name from raw labels (leftmost first, no root label).
    pub fn from_labels<I>(labels: I) -> Result<Name, NameError>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let mut wire = [0u8; MAX_WIRE];
        let mut used = 0;
        for label in labels {
            let label = label.as_ref();
            if label.is_empty() {
                return Err(NameError::EmptyLabel);
            }
            let len = u8::try_from(label.len())
                .ok()
                .filter(|l| usize::from(*l) <= MAX_LABEL)
                .ok_or(NameError::LabelTooLong)?;
            if used + label.len() + 2 > MAX_WIRE {
                return Err(NameError::NameTooLong);
            }
            wire[used] = len;
            wire[used + 1..=used + label.len()].copy_from_slice(label);
            used += label.len() + 1;
        }
        // `wire` is zero-initialised, so the root octet is already in place.
        Ok(Name::from_wire_unchecked(&wire[..=used]))
    }

    /// Wraps already validated wire octets (length-prefixed labels ending in the root octet).
    pub(crate) fn from_wire_unchecked(wire: &[u8]) -> Name {
        Name {
            wire: WireBuf::new(wire),
        }
    }

    /// Parses presentation text. A trailing dot is optional; `.` is the root.
    /// Supports `\.`, `\\`, `\X` and `\DDD` escapes.
    pub fn from_ascii(s: &str) -> Result<Name, NameError> {
        if s.is_empty() {
            return Err(NameError::EmptyLabel);
        }
        if s == "." {
            return Ok(Name::root());
        }
        if !s.is_ascii() {
            return Err(NameError::NonAscii);
        }
        let bytes = s.as_bytes();
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut cur: Vec<u8> = Vec::new();
        let mut i = 0;
        let mut ended_with_dot = false;
        while i < bytes.len() {
            ended_with_dot = false;
            match bytes[i] {
                b'.' => {
                    if cur.is_empty() {
                        return Err(NameError::EmptyLabel);
                    }
                    labels.push(std::mem::take(&mut cur));
                    ended_with_dot = true;
                    i += 1;
                }
                b'\\' => {
                    let next = *bytes.get(i + 1).ok_or(NameError::BadEscape)?;
                    if next.is_ascii_digit() {
                        let digits = bytes.get(i + 1..i + 4).ok_or(NameError::BadEscape)?;
                        if !digits.iter().all(u8::is_ascii_digit) {
                            return Err(NameError::BadEscape);
                        }
                        let value = digits
                            .iter()
                            .fold(0u32, |acc, d| acc * 10 + u32::from(d - b'0'));
                        cur.push(u8::try_from(value).map_err(|_| NameError::BadEscape)?);
                        i += 4;
                    } else {
                        cur.push(next);
                        i += 2;
                    }
                }
                b => {
                    cur.push(b);
                    i += 1;
                }
            }
        }
        if !ended_with_dot {
            labels.push(cur);
        }
        Name::from_labels(labels)
    }

    /// Iterates the labels, leftmost first.
    pub fn labels(&self) -> Labels<'_> {
        Labels { rest: &self.wire }
    }

    /// Number of labels, not counting the root.
    pub fn label_count(&self) -> u8 {
        u8::try_from(self.labels().count()).expect("a name has at most 127 labels")
    }

    /// Length of the uncompressed wire form, including the root octet.
    pub fn wire_len(&self) -> usize {
        self.wire.len()
    }

    /// The uncompressed wire form.
    pub fn as_wire(&self) -> &[u8] {
        &self.wire
    }

    /// True for the root name.
    pub fn is_root(&self) -> bool {
        self.wire.len() == 1
    }

    /// The name without its leftmost label; `None` for the root.
    pub fn parent(&self) -> Option<Name> {
        if self.is_root() {
            return None;
        }
        Some(Name::from_wire_unchecked(
            &self.wire[usize::from(self.wire[0]) + 1..],
        ))
    }

    /// True when `self` equals `other` or lies below it.
    pub fn is_subdomain_of(&self, other: &Name) -> bool {
        let (a, b) = (self.label_count(), other.label_count());
        if a < b {
            return false;
        }
        self.labels()
            .skip(usize::from(a - b))
            .zip(other.labels())
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
    }

    /// A copy with ASCII letters lowercased.
    #[must_use]
    pub fn to_lowercase(&self) -> Name {
        let mut lower = self.clone();
        match &mut lower.wire {
            WireBuf::Inline { len, buf } => buf[..usize::from(*len)].make_ascii_lowercase(),
            WireBuf::Heap(b) if b.iter().any(u8::is_ascii_uppercase) => {
                *b = b.to_ascii_lowercase().into();
            }
            WireBuf::Heap(_) => {}
        }
        lower
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.wire.eq_ignore_ascii_case(&other.wire)
    }
}

impl Eq for Name {}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // One `write` of the lowercased octets (a name is at most 255), not one call per byte.
        let wire: &[u8] = &self.wire;
        let mut lower = [0u8; MAX_WIRE];
        let lower = &mut lower[..wire.len()];
        lower.copy_from_slice(wire);
        lower.make_ascii_lowercase();
        state.write(lower);
    }
}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Name {
    fn cmp(&self, other: &Self) -> Ordering {
        let a: Vec<&[u8]> = self.labels().collect();
        let b: Vec<&[u8]> = other.labels().collect();
        for (x, y) in a.iter().rev().zip(b.iter().rev()) {
            let ord = x
                .iter()
                .map(u8::to_ascii_lowercase)
                .cmp(y.iter().map(u8::to_ascii_lowercase));
            if ord != Ordering::Equal {
                return ord;
            }
        }
        a.len().cmp(&b.len())
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str(".");
        }
        for label in self.labels() {
            for &b in label {
                match b {
                    b'.' | b'\\' | b'"' => write!(f, "\\{}", char::from(b))?,
                    0x21..=0x7e => write!(f, "{}", char::from(b))?,
                    _ => write!(f, "\\{b:03}")?,
                }
            }
            f.write_str(".")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({self})")
    }
}
