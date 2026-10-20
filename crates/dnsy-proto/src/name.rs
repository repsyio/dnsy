use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use crate::NameError;

const MAX_LABEL: usize = 63;
const MAX_WIRE: usize = 255;

/// A domain name stored in uncompressed wire form (length-prefixed labels, ending in the root).
///
/// Equality and hashing are ASCII case-insensitive; ordering is the RFC 4034 6.1 canonical order.
#[derive(Clone)]
pub struct Name {
    wire: Vec<u8>,
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
        Name { wire: vec![0] }
    }

    /// Builds a name from raw labels (leftmost first, no root label).
    pub fn from_labels<I>(labels: I) -> Result<Name, NameError>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let mut wire = Vec::new();
        for label in labels {
            let label = label.as_ref();
            if label.is_empty() {
                return Err(NameError::EmptyLabel);
            }
            let len = u8::try_from(label.len())
                .ok()
                .filter(|l| usize::from(*l) <= MAX_LABEL)
                .ok_or(NameError::LabelTooLong)?;
            wire.push(len);
            wire.extend_from_slice(label);
            if wire.len() + 1 > MAX_WIRE {
                return Err(NameError::NameTooLong);
            }
        }
        wire.push(0);
        Ok(Name { wire })
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
        Some(Name {
            wire: self.wire[usize::from(self.wire[0]) + 1..].to_vec(),
        })
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
        Name {
            wire: self.wire.to_ascii_lowercase(),
        }
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
        for b in &self.wire {
            state.write_u8(b.to_ascii_lowercase());
        }
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
                    b'.' | b'\\' => write!(f, "\\{}", char::from(b))?,
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
