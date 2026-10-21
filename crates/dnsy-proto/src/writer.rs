use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::OnceLock;

use crate::Name;

/// Pointers can only address the first 14 bits of the message.
const MAX_POINTER_OFFSET: usize = 0x4000;

/// A name has at most 127 labels.
const MAX_LABELS: usize = 127;

/// Longest hash chain `find` walks per lookup. Past it the name is simply not compressed, which
/// keeps hostile names engineered to collide from turning encoding quadratic. Ordinary messages
/// never reach it: a chain only grows when two different suffixes share a 64-bit keyed hash.
const MAX_PROBES: usize = 8;

/// Per-process random key mixed into every suffix hash, so which names collide cannot be
/// precomputed by whoever controls names in a message.
fn hash_seed() -> u64 {
    static SEED: OnceLock<u64> = OnceLock::new();
    *SEED.get_or_init(|| RandomState::new().hash_one(0x646e_7379_u64))
}

/// One name suffix already written to the message, found again by comparing wire bytes.
struct Suffix {
    /// Offset of the suffix within the message.
    offset: u16,
    /// Next entry whose suffix hashes to the same value.
    next: Option<u32>,
}

/// A DNS message builder with name compression.
pub struct WireWriter {
    buf: Vec<u8>,
    /// Case-insensitive suffix hash -> first entry of the chain in `suffixes`. The table only holds
    /// offsets: a candidate is verified against the message bytes already written.
    heads: HashMap<u64, u32>,
    suffixes: Vec<Suffix>,
    /// Applied to every suffix hash; all ones except in tests that force collisions.
    pub(crate) hash_mask: u64,
    /// Entries compared by `find` so far (bounded by `MAX_PROBES` per lookup).
    pub(crate) probes: usize,
}

impl Default for WireWriter {
    fn default() -> Self {
        Self {
            buf: Vec::new(),
            heads: HashMap::new(),
            suffixes: Vec::new(),
            hash_mask: u64::MAX,
            probes: 0,
        }
    }
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
        let mut hash = 0xcbf2_9ce4_8422_2325u64 ^ hash_seed();
        for i in (0..count).rev() {
            let from = usize::from(starts[i]);
            let to = from + usize::from(wire[from]) + 1;
            for b in &wire[from..to] {
                hash = (hash ^ u64::from(b.to_ascii_lowercase())).wrapping_mul(0x0100_0000_01b3);
            }
            hashes[i] = hash & self.hash_mask;
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

    fn find(&mut self, hash: u64, suffix: &[u8]) -> Option<u16> {
        let mut entry = self.heads.get(&hash).copied();
        for _ in 0..MAX_PROBES {
            let i = entry?;
            self.probes += 1;
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
