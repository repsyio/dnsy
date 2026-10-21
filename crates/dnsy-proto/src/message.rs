//! DNS message codec (RFC 1035 section 4): sections, name compression, truncation and FORMERR.

use std::collections::HashMap;
use std::fmt;

use crate::{
    Class, Counts, Edns, EdnsOption, HEADER_LEN, Header, Name, PADDING_BLOCK, RData, Rcode,
    RecordType, WireError, WireReader, WireWriter,
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
/// The OPT pseudo-record lives in `edns`, never in `additional`: decode lifts it out, encode writes
/// it last and never drops it when truncating. `header.rcode` is the full extended rcode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
    pub edns: Option<Edns>,
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
    /// More than one OPT record, or an OPT record not owned by the root name.
    BadOpt,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortHeader => f.write_str("message shorter than the header"),
            Self::Wire(e) => write!(f, "{e}"),
            Self::TrailingData => f.write_str("trailing data after the last section"),
            Self::BadOpt => f.write_str("duplicate or misnamed OPT record"),
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
    /// The rcode does not fit in the 12 bits the header and OPT can carry.
    BadRcode,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyRecords => f.write_str("more than 65535 entries in a section"),
            Self::RdataTooLong => f.write_str("RDATA longer than 65535 octets"),
            Self::BadRdata(e) => write!(f, "unencodable RDATA: {e}"),
            Self::DoesNotFit => f.write_str("header, questions and OPT exceed the size limit"),
            Self::BadRcode => f.write_str("rcode wider than 12 bits"),
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
        // Capacity comes from the counts but never exceeds what the remaining octets could hold
        // (a question takes at least 5, a record at least 11), so a forged count cannot make the
        // allocation larger than the packet justifies.
        let mut questions = Vec::with_capacity(reserve(counts.questions, r.remaining(), 5));
        for _ in 0..counts.questions {
            questions.push(read_question(&mut r)?);
        }
        let mut edns = None;
        let mut section = |n: u16, lift_opt: bool| {
            let mut records = Vec::with_capacity(reserve(n, r.remaining(), 11));
            for _ in 0..n {
                match read_record(&mut r, lift_opt)? {
                    Parsed::Record(rec) => records.push(rec),
                    Parsed::Opt(opt) if edns.is_none() => edns = Some(opt),
                    Parsed::Opt(_) => return Err(DecodeError::BadOpt),
                }
            }
            Ok::<_, DecodeError>(records)
        };
        let answers = section(counts.answers, false)?;
        let authority = section(counts.authority, false)?;
        let additional = section(counts.additional, true)?;
        if r.remaining() != 0 {
            return Err(DecodeError::TrailingData);
        }
        let mut header = header;
        if let Some(e) = &edns {
            header.rcode =
                Rcode::from(u16::from(e.ext_rcode) << 4 | (u16::from(header.rcode) & 0xF));
        }
        Ok(Message {
            header,
            questions,
            answers,
            authority,
            additional,
            edns,
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

        let mut w = WireWriter::with_capacity(self.size_hint(max_len));
        w.write_bytes(&[0; HEADER_LEN]);
        for q in &self.questions {
            w.write_name(&q.name);
            w.write_u16(q.qtype.into());
            w.write_u16(q.qclass.into());
        }
        let questions_end = w.len();

        let mut body: Vec<Entry<'_>> =
            Vec::with_capacity(self.answers.len() + self.authority.len() + self.additional.len());
        for (s, records) in [&self.answers, &self.authority, &self.additional]
            .into_iter()
            .enumerate()
        {
            for rec in records.iter().filter(|r| !is_opt(s, r)) {
                write_record(&mut w, rec, true)?;
                body.push(Entry {
                    section: s,
                    rec,
                    end: w.len(),
                });
            }
        }
        let body_end = w.len();
        let rcode = u16::from(self.header.rcode);
        let mut opt_count = 0u16;
        if let Some(edns) = &self.edns {
            let ext = u8::try_from(rcode >> 4).map_err(|_| EncodeError::BadRcode)?;
            edns.encode(ext, &mut w)?;
            opt_count = 1;
        } else if rcode > 0xF {
            return Err(EncodeError::BadRcode);
        }
        let opt_len = w.len() - body_end;

        // A prefix of `k` records holds only whole sets when `rrset_end(i) < k` for every i < k.
        let mut keep = 0;
        let mut reach = 0;
        let last_of = (body.len() > SCAN_LIMIT).then(|| rrset_ends(&body));
        for i in 0..body.len() {
            let end = match &last_of {
                Some(ends) => ends[i],
                None => rrset_end(&body, i),
            };
            reach = reach.max(end);
            if body[i].end + opt_len > max_len {
                break;
            }
            if reach == i {
                keep = i + 1;
            }
        }
        let cut = if keep == 0 {
            questions_end
        } else {
            body[keep - 1].end
        };
        if cut + opt_len > max_len {
            return Err(EncodeError::DoesNotFit);
        }

        let mut counts = Counts {
            questions: question_count,
            additional: opt_count,
            ..Counts::default()
        };
        for e in &body[..keep] {
            match e.section {
                ANSWER => counts.answers += 1,
                AUTHORITY => counts.authority += 1,
                _ => counts.additional += 1,
            }
        }
        let mut header = self.header;
        header.rcode = Rcode::from(rcode & 0xF);
        header.tc |= body[keep..].iter().any(|e| e.section != ADDITIONAL);

        // The message was written straight into the output buffer: drop the records that do not
        // fit by sliding the OPT record down over them.
        let mut out = w.finish();
        out.copy_within(body_end..body_end + opt_len, cut);
        out.truncate(cut + opt_len);
        out[..HEADER_LEN].copy_from_slice(&header.encode(counts));
        Ok(out)
    }

    /// A capacity that fits most encodings in one allocation without exceeding `max_len`.
    fn size_hint(&self, max_len: usize) -> usize {
        let owners = self
            .questions
            .iter()
            .map(|q| q.name.wire_len() + 4)
            .chain(
                [&self.answers, &self.authority, &self.additional]
                    .into_iter()
                    .flatten()
                    .map(|r| r.name.wire_len().min(2) + 10 + 16),
            )
            .sum::<usize>();
        (HEADER_LEN + owners + 16).min(max_len).min(1 << 14)
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
            edns: None,
        }
    }

    /// A BADVERS response to a query whose EDNS version is not supported (RFC 6891 6.1.3):
    /// version 0 OPT, the query's questions, and no data.
    pub fn badvers_for(query: &Message) -> Message {
        let mut response = Message::response_to(query);
        response.header.rcode = Rcode::BadVers;
        response.edns = Some(Edns::default());
        response
    }

    /// Adds an Extended DNS Error (RFC 8914) to the response, creating the OPT record when absent.
    /// Several errors may be attached; each call appends one.
    pub fn set_ede(&mut self, code: u16, text: &str) {
        self.edns
            .get_or_insert_with(Edns::default)
            .options
            .push(EdnsOption::ExtendedError {
                code,
                text: text.to_owned(),
            });
    }

    /// Like [`Message::encode`], but pads the OPT record so the message is a multiple of
    /// [`PADDING_BLOCK`] octets (RFC 8467). Callers use it for `DoT` and `DoH` responses when the query
    /// carried a Padding option ([`Edns::has_padding`]). Messages without OPT, and messages whose
    /// padded size would exceed `max_len`, get as much padding as fits.
    pub fn encode_padded(&self, max_len: usize) -> Result<Vec<u8>, EncodeError> {
        let mut unpadded = self.clone();
        if let Some(e) = &mut unpadded.edns {
            e.options.retain(|o| !matches!(o, EdnsOption::Padding(_)));
        }
        let plain = unpadded.encode(max_len)?;
        let Some(edns) = &mut unpadded.edns else {
            return Ok(plain);
        };
        let max_len = max_len.min(usize::from(u16::MAX));
        let with_option = plain.len() + 4;
        let pad = (PADDING_BLOCK - with_option % PADDING_BLOCK) % PADDING_BLOCK;
        let Some(room) = max_len.checked_sub(with_option) else {
            return Ok(plain);
        };
        edns.options.push(EdnsOption::Padding(
            u16::try_from(pad.min(room)).unwrap_or(0),
        ));
        unpadded.encode(max_len)
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
            edns: None,
        };
        let mut response = Message::response_to(&query);
        response.header.rcode = Rcode::FormErr;
        response.encode(usize::from(u16::MAX)).ok()
    }
}

/// A record of the message body together with the offset just past its encoding.
struct Entry<'a> {
    section: usize,
    rec: &'a Record,
    end: usize,
}

/// Bodies up to this many records find record set boundaries by scanning; larger ones use a map.
const SCAN_LIMIT: usize = 64;

fn same_rrset(a: &Entry<'_>, b: &Entry<'_>) -> bool {
    a.section == b.section
        && a.rec.rtype == b.rec.rtype
        && a.rec.class == b.rec.class
        && a.rec.name == b.rec.name
}

/// Index of the last member of record `i`'s record set. Sets are contiguous in practice, so the
/// search runs backwards from the end of the section and usually stops within a few records.
fn rrset_end(body: &[Entry<'_>], i: usize) -> usize {
    (i + 1..body.len())
        .rev()
        .find(|&j| same_rrset(&body[i], &body[j]))
        .unwrap_or(i)
}

/// `rrset_end` for every record, through a map (for large bodies).
fn rrset_ends(body: &[Entry<'_>]) -> Vec<usize> {
    let mut last_of: HashMap<(usize, &Name, RecordType, Class), usize> =
        HashMap::with_capacity(body.len());
    for (i, e) in body.iter().enumerate() {
        last_of.insert((e.section, &e.rec.name, e.rec.rtype, e.rec.class), i);
    }
    body.iter()
        .map(|e| last_of[&(e.section, &e.rec.name, e.rec.rtype, e.rec.class)])
        .collect()
}

/// Capacity for `count` entries of at least `min_size` octets each in `remaining` octets.
fn reserve(count: u16, remaining: usize, min_size: usize) -> usize {
    usize::from(count).min(remaining / min_size)
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

enum Parsed {
    Record(Record),
    Opt(Edns),
}

fn read_record(r: &mut WireReader<'_>, lift_opt: bool) -> Result<Parsed, DecodeError> {
    let name = r.read_name()?;
    let rtype = RecordType::from(r.read_u16()?);
    let raw_class = r.read_u16()?;
    let class = Class::from(raw_class);
    let ttl = r.read_u32()?;
    let len = usize::from(r.read_u16()?);
    if rtype == RecordType::Opt {
        if !lift_opt || !name.is_root() {
            return Err(DecodeError::BadOpt);
        }
        return Ok(Parsed::Opt(Edns::decode(
            raw_class,
            ttl,
            r.read_bytes(len)?,
        )?));
    }
    let data = RData::decode(rtype, r, len)?;
    Ok(Parsed::Record(Record {
        name,
        rtype,
        class,
        ttl,
        data,
    }))
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
