//! dnsy-proto: in-house DNS wire format, standard library only.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    reason = "fallible constructors and accessors are self-describing; error enums are documented"
)]

mod bitmap;
pub mod canonical;
mod edns;
mod error;
mod header;
mod message;
mod name;
mod rdata;
mod reader;
mod types;
mod writer;

pub use bitmap::TypeBitmap;
pub use edns::{DEFAULT_UDP_PAYLOAD, EDNS_VERSION, Edns, EdnsOption, PADDING_BLOCK, ede};
pub use error::{NameError, WireError};
pub use header::{Counts, HEADER_LEN, Header};
pub use message::{DecodeError, EncodeError, Message, Question, Record};
pub use name::{Labels, Name};
pub use rdata::{
    Dnskey, Ds, Nsec3, Nsec3Param, Rrsig, base32hex_decode, base32hex_encode, format_timestamp,
    parse_timestamp, serial_gt, serial_lt,
};
pub use rdata::{RData, RdataParseError, Soa};
pub use reader::WireReader;
pub use types::{Class, Opcode, Rcode, RecordType};
pub use writer::WireWriter;

#[cfg(test)]
mod tests;
