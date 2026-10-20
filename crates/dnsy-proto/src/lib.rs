//! dnsy-proto: in-house DNS wire format, standard library only.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    reason = "fallible constructors and accessors are self-describing; error enums are documented"
)]

mod compress;
mod error;
mod header;
mod message;
mod name;
mod rdata;
mod reader;
mod types;
mod writer;

pub use error::{NameError, WireError};
pub use header::{Counts, HEADER_LEN, Header};
pub use message::{DecodeError, EncodeError, Message, Question, RData, Record, Soa};
pub use name::{Labels, Name};
pub use rdata::{RData, RdataParseError, Soa};
pub use reader::WireReader;
pub use types::{Class, Opcode, Rcode, RecordType};
pub use writer::WireWriter;

#[cfg(test)]
mod tests;
