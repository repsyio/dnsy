use crate::{Name, NameError, WireError};

const MAX_HOPS: usize = 128;

/// A bounds-checked cursor over a DNS message.
pub struct WireReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Truncated)?;
        let out = self.buf.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        Ok(out)
    }

    pub fn read_u8(&mut self) -> Result<u8, WireError> {
        Ok(self.read_bytes(1)?[0])
    }

    pub fn read_u16(&mut self) -> Result<u16, WireError> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn read_u32(&mut self) -> Result<u32, WireError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a possibly compressed name. Pointers must point strictly before the
    /// pointer itself and are followed at most 128 times.
    pub fn read_name(&mut self) -> Result<Name, WireError> {
        let mut labels: Vec<&[u8]> = Vec::new();
        let mut total = 1usize;
        let mut cursor = self.pos;
        let mut resume: Option<usize> = None;
        let mut hops = 0;
        loop {
            let len = *self.buf.get(cursor).ok_or(WireError::Truncated)?;
            match len & 0xC0 {
                0x00 => {
                    cursor += 1;
                    if len == 0 {
                        break;
                    }
                    let end = cursor + usize::from(len);
                    let label = self.buf.get(cursor..end).ok_or(WireError::Truncated)?;
                    total += label.len() + 1;
                    if total > 255 {
                        return Err(NameError::NameTooLong.into());
                    }
                    labels.push(label);
                    cursor = end;
                }
                0xC0 => {
                    let low = *self.buf.get(cursor + 1).ok_or(WireError::Truncated)?;
                    let target = usize::from(len & 0x3F) << 8 | usize::from(low);
                    hops += 1;
                    if target >= cursor || hops > MAX_HOPS {
                        return Err(WireError::BadPointer);
                    }
                    resume.get_or_insert(cursor + 2);
                    cursor = target;
                }
                _ => return Err(WireError::BadLabelType),
            }
        }
        self.pos = resume.unwrap_or(cursor);
        Ok(Name::from_labels(labels)?)
    }
}
