use crate::{Opcode, Rcode, WireError};

/// Length of the fixed DNS header.
pub const HEADER_LEN: usize = 12;

/// The section counts that follow the ID and flags in the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    pub questions: u16,
    pub answers: u16,
    pub authority: u16,
    pub additional: u16,
}

/// The DNS header flags and identifiers (RFC 1035 4.1.1, with AD and CD from RFC 4035).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(clippy::struct_excessive_bools, reason = "mirrors the wire flag bits")]
pub struct Header {
    pub id: u16,
    pub qr: bool,
    pub opcode: Opcode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub ad: bool,
    pub cd: bool,
    pub rcode: Rcode,
}

impl Header {
    /// Encodes the 12-byte header. Only the low four bits of the rcode are written.
    pub fn encode(&self, counts: Counts) -> [u8; HEADER_LEN] {
        let mut flags = u16::from(u8::from(self.opcode) & 0xF) << 11;
        flags |= u16::from(self.qr) << 15;
        flags |= u16::from(self.aa) << 10;
        flags |= u16::from(self.tc) << 9;
        flags |= u16::from(self.rd) << 8;
        flags |= u16::from(self.ra) << 7;
        flags |= u16::from(self.ad) << 5;
        flags |= u16::from(self.cd) << 4;
        flags |= u16::from(self.rcode) & 0xF;
        let mut out = [0u8; HEADER_LEN];
        for (chunk, v) in out.as_chunks_mut::<2>().0.iter_mut().zip([
            self.id,
            flags,
            counts.questions,
            counts.answers,
            counts.authority,
            counts.additional,
        ]) {
            *chunk = v.to_be_bytes();
        }
        out
    }

    /// Decodes the header from the start of `buf`.
    pub fn decode(buf: &[u8]) -> Result<(Header, Counts), WireError> {
        let raw = buf.get(..HEADER_LEN).ok_or(WireError::Truncated)?;
        let word = |i: usize| u16::from_be_bytes([raw[i * 2], raw[i * 2 + 1]]);
        let flags = word(1);
        let header = Header {
            id: word(0),
            qr: flags & 0x8000 != 0,
            opcode: Opcode::from(u8::try_from((flags >> 11) & 0xF).expect("four bits")),
            aa: flags & 0x0400 != 0,
            tc: flags & 0x0200 != 0,
            rd: flags & 0x0100 != 0,
            ra: flags & 0x0080 != 0,
            ad: flags & 0x0020 != 0,
            cd: flags & 0x0010 != 0,
            rcode: Rcode::from(flags & 0xF),
        };
        let counts = Counts {
            questions: word(2),
            answers: word(3),
            authority: word(4),
            additional: word(5),
        };
        Ok((header, counts))
    }
}
