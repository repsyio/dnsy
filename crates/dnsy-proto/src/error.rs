use std::fmt;

/// Errors building a [`crate::Name`] from presentation text or labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    /// An empty label (for example `a..b`) or an empty name.
    EmptyLabel,
    /// A label longer than 63 octets.
    LabelTooLong,
    /// An encoded name longer than 255 octets.
    NameTooLong,
    /// A malformed `\` escape.
    BadEscape,
    /// A non-ASCII character in presentation text.
    NonAscii,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyLabel => "empty label",
            Self::LabelTooLong => "label longer than 63 octets",
            Self::NameTooLong => "name longer than 255 octets",
            Self::BadEscape => "malformed escape",
            Self::NonAscii => "non-ASCII character",
        })
    }
}

impl std::error::Error for NameError {}

/// Errors reading or writing the DNS wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The buffer ended before the field did.
    Truncated,
    /// A compression pointer that does not point strictly backwards, or too many hops.
    BadPointer,
    /// A label type that is neither a plain label nor a pointer.
    BadLabelType,
    /// A decoded name violating the length limits.
    BadName(NameError),
    /// RDATA whose content does not match its type or declared length.
    BadRdata,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("message truncated"),
            Self::BadPointer => f.write_str("bad compression pointer"),
            Self::BadLabelType => f.write_str("unsupported label type"),
            Self::BadName(e) => write!(f, "bad name: {e}"),
            Self::BadRdata => f.write_str("malformed rdata"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<NameError> for WireError {
    fn from(e: NameError) -> Self {
        Self::BadName(e)
    }
}
