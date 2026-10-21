use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

use crate::Name;

/// Pointers can only address the first 14 bits of the message.
const MAX_POINTER_OFFSET: usize = 0x4000;

/// A name has at most 127 labels.
const MAX_LABELS: usize = 127;

/// The compression table is keyed by an already mixed 64-bit hash; hashing it again is wasted work.
#[derive(Default)]
struct PassThrough(u64);

impl Hasher for PassThrough {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 = self.0 << 8 | u64::from(*b);
        }
    }

    fn write_u64(&mut self, v: u64) {
        self.0 = v;
    }
}

/// One name suffix already written to the message, found again by comparing wire bytes.
struct Suffix {
    /// Offset of the suffix within the message.
    offset: u16,
    /// Next entry whose suffix hashes to the same value.
    next: Option<u32>,
}

/// A DNS message builder with name compression.
#[derive(Default)]
pub struct WireWriter {
    buf: Vec<u8>,
    /// Case-insensitive suffix hash -> first entry of the chain in `suffixes`. The table only holds
    /// offsets: a candidate is verified against the message bytes already written.
    heads: HashMap<u64, u32, BuildHasherDefault<PassThrough>>,
    suffixes: Vec<Suffix>,
}

impl WireWriter {
    pub fn new() -> Self {
        Self::default()
    }

    /// A writer whose message buffer holds `capacity` octets before it has to grow.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            ..Self::default()
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn write_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    /// Overwrites two bytes at `at` (for example an RDLENGTH written afterwards).
    ///
    /// # Panics
    /// Panics when `at + 2` exceeds the written length.
    pub fn patch_u16(&mut self, at: usize, v: u16) {
        self.buf[at..at + 2].copy_from_slice(&v.to_be_bytes());
    }

    /// Writes a name, replacing the longest already-written suffix with a pointer.
    pub fn write_name(&mut self, name: &Name) {
        let wire = name.as_wire();
        // Suffix hashes, computed right to left so each is linear in the label it adds.
        let mut starts = [0u8; MAX_LABELS];
        let mut count = 0;
        let mut at = 0;
        while wire[at] != 0 {
            starts[count] = u8::try_from(at).expect("a name is at most 255 octets");
            count += 1;
            at += usize::from(wire[at]) + 1;
        }
        let mut hashes = [0u64; MAX_LABELS];
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for i in (0..count).rev() {
            let from = usize::from(starts[i]);
            let to = from + usize::from(wire[from]) + 1;
            for b in &wire[from..to] {
                hash = (hash ^ u64::from(b.to_ascii_lowercase())).wrapping_mul(0x0100_0000_01b3);
            }
            hashes[i] = hash;
        }

        for i in 0..count {
            let from = usize::from(starts[i]);
            let suffix = &wire[from..];
            if let Some(target) = self.find(hashes[i], suffix) {
                self.write_u16(0xC000 | target);
                return;
            }
            if let Ok(offset) = u16::try_from(self.buf.len())
                && usize::from(offset) < MAX_POINTER_OFFSET
            {
                self.remember(hashes[i], offset);
            }
            let next = from + usize::from(wire[from]) + 1;
            self.buf.extend_from_slice(&wire[from..next]);
        }
        self.buf.push(0);
    }

    fn remember(&mut self, hash: u64, offset: u16) {
        let index = u32::try_from(self.suffixes.len()).expect("at most 16384 entries");
        let next = self.heads.insert(hash, index);
        self.suffixes.push(Suffix { offset, next });
    }

    fn find(&self, hash: u64, suffix: &[u8]) -> Option<u16> {
        let mut entry = self.heads.get(&hash).copied();
        while let Some(i) = entry {
            let candidate = &self.suffixes[i as usize];
            if self.matches(usize::from(candidate.offset), suffix) {
                return Some(candidate.offset);
            }
            entry = candidate.next;
        }
        None
    }

    /// Whether the (possibly compressed) name written at `pos` equals `suffix`, ignoring ASCII case.
    fn matches(&self, mut pos: usize, suffix: &[u8]) -> bool {
        let mut at = 0;
        loop {
            let Some(&len) = self.buf.get(pos) else {
                return false;
            };
            if len & 0xC0 == 0xC0 {
                let Some(&low) = self.buf.get(pos + 1) else {
                    return false;
                };
                pos = usize::from(len & 0x3F) << 8 | usize::from(low);
                continue;
            }
            if suffix[at] != len {
                return false;
            }
            if len == 0 {
                return true;
            }
            let n = usize::from(len);
            let Some(label) = self.buf.get(pos + 1..pos + 1 + n) else {
                return false;
            };
            if !label.eq_ignore_ascii_case(&suffix[at + 1..=at + n]) {
                return false;
            }
            pos += n + 1;
            at += n + 1;
        }
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}
