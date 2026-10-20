use std::collections::HashMap;

use crate::Name;

/// Pointers can only address the first 14 bits of the message.
const MAX_POINTER_OFFSET: usize = 0x4000;

/// A DNS message builder with name compression.
#[derive(Default)]
pub struct WireWriter {
    buf: Vec<u8>,
    /// Lowercased wire-form suffix -> offset of its first occurrence.
    names: HashMap<Vec<u8>, u16>,
}

impl WireWriter {
    pub fn new() -> Self {
        Self::default()
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
        let mut at = 0;
        while wire[at] != 0 {
            let suffix = wire[at..].to_ascii_lowercase();
            if let Some(&target) = self.names.get(&suffix) {
                self.write_u16(0xC000 | target);
                return;
            }
            if let Ok(offset) = u16::try_from(self.buf.len())
                && usize::from(offset) < MAX_POINTER_OFFSET
            {
                self.names.insert(suffix, offset);
            }
            let next = at + usize::from(wire[at]) + 1;
            self.buf.extend_from_slice(&wire[at..next]);
            at = next;
        }
        self.buf.push(0);
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}
