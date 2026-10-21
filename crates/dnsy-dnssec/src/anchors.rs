//! Trust anchors as written in configuration and anchor files.

use std::fmt;

/// A trust anchor record that does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchorError(String);

impl fmt::Display for TrustAnchorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TrustAnchorError {}

/// A parsed trust anchor DS record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchor {
    /// Key tag.
    pub key_tag: u16,
    /// DNSSEC algorithm number.
    pub algorithm: u8,
    /// Digest type (1 SHA-1, 2 SHA-256, 4 SHA-384).
    pub digest_type: u8,
    /// Digest bytes.
    pub digest: Vec<u8>,
}

impl TrustAnchor {
    /// Parse `keytag algorithm digest-type digest-hex`.
    ///
    /// # Errors
    /// Returns [`TrustAnchorError`] on a malformed record.
    pub fn parse(text: &str) -> Result<Self, TrustAnchorError> {
        let bad = |why: &str| TrustAnchorError(format!("trust anchor `{text}`: {why}"));
        let mut parts = text.split_whitespace();
        let mut next = |what: &str| parts.next().ok_or_else(|| bad(&format!("missing {what}")));
        let key_tag = next("key tag")?
            .parse()
            .map_err(|_| bad("invalid key tag"))?;
        let algorithm = next("algorithm")?
            .parse()
            .map_err(|_| bad("invalid algorithm"))?;
        let digest_type: u8 = next("digest type")?
            .parse()
            .map_err(|_| bad("invalid digest type"))?;
        let hex = next("digest")?;
        if parts.next().is_some() {
            return Err(bad("trailing data"));
        }
        let digest = decode_hex(hex).ok_or_else(|| bad("digest is not hex"))?;
        let expected = match digest_type {
            1 => 20,
            2 => 32,
            4 => 48,
            _ => return Err(bad("unsupported digest type")),
        };
        if digest.len() != expected {
            return Err(bad("digest length does not match digest type"));
        }
        Ok(Self {
            key_tag,
            algorithm,
            digest_type,
            digest,
        })
    }
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) || !hex.is_ascii() {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_2024: &str =
        "38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16";

    #[test]
    fn parses_a_root_ds() {
        let ta = TrustAnchor::parse(ROOT_2024).unwrap();
        assert_eq!(
            (ta.key_tag, ta.algorithm, ta.digest_type, ta.digest.len()),
            (38696, 8, 2, 32)
        );
    }

    #[test]
    fn rejects_malformed_records() {
        for bad in [
            "",
            "1",
            "x 8 2 aa",
            "1 x 2 aa",
            "1 8 x aa",
            "1 8 2",
            "1 8 2 zz",
            "1 8 2 abc",
            "1 8 9 aa",
            "1 8 1 aabb",
            &format!("{ROOT_2024} extra"),
            "1 8 2 éé",
        ] {
            assert!(TrustAnchor::parse(bad).is_err(), "{bad}");
        }
        assert!(TrustAnchor::parse(&format!("1 8 1 {}", "ab".repeat(20))).is_ok());
        assert!(TrustAnchor::parse(&format!("1 8 4 {}", "ab".repeat(48))).is_ok());
    }
}
