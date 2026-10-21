//! SPKI pinning: the SHA-256 of a certificate's `SubjectPublicKeyInfo` (RFC 7469 style).

use ring::digest::{SHA256, digest};

/// Reads one DER element, returning (tag, whole element including header, rest).
fn element(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, tail) = buf.split_first()?;
    let (&first, tail) = tail.split_first()?;
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 3 || tail.len() < n {
            return None;
        }
        let len = tail[..n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, 2 + n)
    };
    let total = header.checked_add(len)?;
    (buf.len() >= total).then(|| (tag, &buf[..total], &buf[total..]))
}

/// The content of a DER element.
fn content(el: &[u8]) -> &[u8] {
    let n = if el[1] < 0x80 {
        0
    } else {
        usize::from(el[1] & 0x7f)
    };
    &el[2 + n..]
}

/// SHA-256 of the `SubjectPublicKeyInfo` of a DER-encoded X.509 certificate, or `None` when the
/// certificate cannot be parsed.
pub(super) fn spki_sha256(cert: &[u8]) -> Option<[u8; 32]> {
    let (_, cert, _) = element(cert)?;
    let (_, tbs, _) = element(content(cert))?;
    let mut rest = content(tbs);
    let (tag, _, tail) = element(rest)?;
    // Optional [0] version, then serial, signature algorithm, issuer, validity, subject.
    rest = if tag == 0xa0 { tail } else { rest };
    for _ in 0..5 {
        rest = element(rest)?.2;
    }
    let (tag, spki, _) = element(rest)?;
    (tag == 0x30).then(|| digest(&SHA256, spki).as_ref().try_into().ok())?
}
