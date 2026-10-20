//! DNS message codec (RFC 1035 section 4): sections, name compression, truncation and FORMERR.

use std::collections::HashMap;
use std::fmt;

use crate::{
    Class, Counts, HEADER_LEN, Header, Name, RData, Rcode, RecordType, WireError, WireReader,
    WireWriter,
};

/// A question section entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub qtype: RecordType,
    pub qclass: Class,
}

/// A resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    pub rtype: RecordType,
    pub class: Class,
    pub ttl: u32,
    pub data: RData,
}

/// A complete DNS message.
///
/// An OPT pseudo-record stays in `additional` until EDNS support lifts it into its own field; on
/// encode it is always written last and is never dropped by truncation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

/// Why a message could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Fewer than 12 octets: the header is unreadable, so the packet is dropped.
    ShortHeader,
    /// A malformed field, or a section count larger than the data.
    Wire(WireError),
    /// Octets left over after the last section.
    TrailingData,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortHeader => f.write_str("message shorter than the header"),
            Self::Wire(e) => write!(f, "{e}"),
            Self::TrailingData => f.write_str("trailing data after the last section"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl From<WireError> for DecodeError {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}

/// Why a message could not be encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// A section holds more than 65535 entries.
    TooManyRecords,
    /// A record's RDATA is longer than 65535 octets.
    RdataTooLong,
    /// RDATA that cannot be represented on the wire (for example an invalid CAA tag).
    BadRdata(WireError),
    /// The header, questions and OPT alone exceed the size limit.
    DoesNotFit,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyRecords => f.write_str("more than 65535 entries in a section"),
            Self::RdataTooLong => f.write_str("RDATA longer than 65535 octets"),
            Self::BadRdata(e) => write!(f, "unencodable RDATA: {e}"),
            Self::DoesNotFit => f.write_str("header, questions and OPT exceed the size limit"),
        }
    }
}

impl std::error::Error for EncodeError {}

const ANSWER: usize = 0;
const AUTHORITY: usize = 1;
const ADDITIONAL: usize = 2;

impl Message {
    /// Decodes a message, validating every section count against the data.
    pub fn decode(buf: &[u8]) -> Result<Message, DecodeError> {
        let (header, counts) = Header::decode(buf).map_err(|_| DecodeError::ShortHeader)?;
        let mut r = WireReader::new(buf);
        r.read_bytes(HEADER_LEN)?;
        // Collecting through `Result` keeps allocation proportional to what actually parsed,
        // not to the (attacker-controlled) counts.
        let questions = (0..counts.questions)
            .map(|_| read_question(&mut r))
            .collect::<Result<Vec<_>, _>>()?;
        let mut section = |n: u16| {
            (0..n)
                .map(|_| read_record(&mut r))
                .collect::<Result<Vec<_>, _>>()
        };
        let answers = section(counts.answers)?;
        let authority = section(counts.authority)?;
        let additional = section(counts.additional)?;
        if r.remaining() != 0 {
            return Err(DecodeError::TrailingData);
        }
        Ok(Message {
            header,
            questions,
            answers,
            authority,
            additional,
        })
    }

    /// Encodes the message in at most `max_len` octets (capped at 65535), compressing names.
    ///
    /// When it does not fit, whole record sets are dropped from the end (additional, then authority,
    /// then answers); OPT records are kept and written last. TC is set when an answer or
    /// authority record set was dropped; dropping only additional data leaves TC alone (RFC 2181 9).
    pub fn encode(&self, max_len: usize) -> Result<Vec<u8>, EncodeError> {
        let max_len = max_len.min(usize::from(u16::MAX));
        let question_count =
            u16::try_from(self.questions.len()).map_err(|_| EncodeError::TooManyRecords)?;
        for s in [&self.answers, &self.authority, &self.additional] {
            u16::try_from(s.len()).map_err(|_| EncodeError::TooManyRecords)?;
        }

        let mut w = WireWriter::new();
        w.write_bytes(&[0; HEADER_LEN]);
        for q in &self.questions {
            w.write_name(&q.name);
            w.write_u16(q.qtype.into());
            w.write_u16(q.qclass.into());
        }
        let questions_end = w.len();

        let body: Vec<(usize, &Record)> = [&self.answers, &self.authority, &self.additional]
            .into_iter()
            .enumerate()
            .flat_map(|(s, records)| records.iter().map(move |r| (s, r)))
            .filter(|(s, r)| !is_opt(*s, r))
            .collect();
        let mut ends = Vec::with_capacity(body.len());
        for (_, rec) in &body {
            write_record(&mut w, rec, true)?;
            ends.push(w.len());
        }
        let mut opt = WireWriter::new();
        let mut opt_count = 0u16;
        for rec in self
            .additional
            .iter()
            .filter(|r| r.rtype == RecordType::Opt)
        {
            write_record(&mut opt, rec, false)?;
            opt_count += 1;
        }
        let opt = opt.finish();
        let full = w.finish();

        // `last[i]` is the index of the final member of record i's RRset within its section;
        // a prefix of `k` records holds only whole RRsets when every `last[i] < k` for i < k.
        let mut last_of: HashMap<(usize, &Name, RecordType, Class), usize> = HashMap::new();
        for (i, (s, rec)) in body.iter().enumerate() {
            last_of.insert((*s, &rec.name, rec.rtype, rec.class), i);
        }
        let mut keep = 0;
        let mut reach = 0;
        for (i, (s, rec)) in body.iter().enumerate() {
            reach = reach.max(last_of[&(*s, &rec.name, rec.rtype, rec.class)]);
            if ends[i] + opt.len() > max_len {
                break;
            }
            if reach == i {
                keep = i + 1;
            }
        }
        let cut = if keep == 0 {
            questions_end
        } else {
            ends[keep - 1]
        };
        if cut + opt.len() > max_len {
            return Err(EncodeError::DoesNotFit);
        }

        let mut counts = Counts {
            questions: question_count,
            additional: opt_count,
            ..Counts::default()
        };
        for (s, _) in &body[..keep] {
            match *s {
                ANSWER => counts.answers += 1,
                AUTHORITY => counts.authority += 1,
                _ => counts.additional += 1,
            }
        }
        let mut header = self.header;
        header.tc |= body[keep..].iter().any(|(s, _)| *s != ADDITIONAL);

        let mut out = Vec::with_capacity(cut + opt.len());
        out.extend_from_slice(&header.encode(counts));
        out.extend_from_slice(&full[HEADER_LEN..cut]);
        out.extend_from_slice(&opt);
        Ok(out)
    }

    /// An empty response to `query`: same id, opcode, RD, CD and questions, QR set, NOERROR.
    pub fn response_to(query: &Message) -> Message {
        Message {
            header: Header {
                id: query.header.id,
                qr: true,
                opcode: query.header.opcode,
                aa: false,
                tc: false,
                rd: query.header.rd,
                ra: false,
                ad: false,
                cd: query.header.cd,
                rcode: Rcode::NoError,
            },
            questions: query.questions.clone(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    /// A FORMERR response for a malformed query, echoing its id and, when it parses, the first
    /// question. `None` when the header is unreadable or the packet is itself a response (so
    /// two servers never bounce FORMERRs at each other); the caller drops the packet then.
    pub fn formerr_for(buf: &[u8]) -> Option<Vec<u8>> {
        let (header, counts) = Header::decode(buf).ok()?;
        if header.qr {
            return None;
        }
        let question = (counts.questions > 0)
            .then(|| {
                let mut r = WireReader::new(buf);
                r.read_bytes(HEADER_LEN).ok()?;
                read_question(&mut r).ok()
            })
            .flatten();
        let query = Message {
            header,
            questions: question.into_iter().collect(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        };
        let mut response = Message::response_to(&query);
        response.header.rcode = Rcode::FormErr;
        response.encode(usize::from(u16::MAX)).ok()
    }
}

fn is_opt(section: usize, rec: &Record) -> bool {
    section == ADDITIONAL && rec.rtype == RecordType::Opt
}

fn read_question(r: &mut WireReader<'_>) -> Result<Question, DecodeError> {
    Ok(Question {
        name: r.read_name()?,
        qtype: r.read_u16()?.into(),
        qclass: r.read_u16()?.into(),
    })
}

fn read_record(r: &mut WireReader<'_>) -> Result<Record, DecodeError> {
    let name = r.read_name()?;
    let rtype = RecordType::from(r.read_u16()?);
    let class = Class::from(r.read_u16()?);
    let ttl = r.read_u32()?;
    let len = usize::from(r.read_u16()?);
    let data = RData::decode(rtype, r, len)?;
    Ok(Record {
        name,
        rtype,
        class,
        ttl,
        data,
    })
}

fn write_record(w: &mut WireWriter, rec: &Record, compress_owner: bool) -> Result<(), EncodeError> {
    if compress_owner {
        w.write_name(&rec.name);
    } else {
        w.write_bytes(rec.name.as_wire());
    }
    w.write_u16(rec.rtype.into());
    w.write_u16(rec.class.into());
    w.write_u32(rec.ttl);
    let len_at = w.len();
    w.write_u16(0);
    rec.data.encode(w).map_err(EncodeError::BadRdata)?;
    let len = u16::try_from(w.len() - len_at - 2).map_err(|_| EncodeError::RdataTooLong)?;
    w.patch_u16(len_at, len);
    Ok(())
}

#[cfg(test)]
#[path = "message_tests.rs"]
mod tests;
