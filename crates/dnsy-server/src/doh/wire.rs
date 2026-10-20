//! Pure request/response helpers: RFC 8484 parameter decoding, token extraction, TTLs.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dnsy_proto::Message;

/// Largest DNS message in a request or response (RFC 8484 section 6).
pub(crate) const MAX_MESSAGE: usize = 65_535;
/// Longest base64url `dns` parameter that can decode to [`MAX_MESSAGE`] octets.
const MAX_DNS_PARAM: usize = MAX_MESSAGE.div_ceil(3) * 4;
/// Longest accepted path token (real tokens are about 60 characters).
pub(crate) const MAX_TOKEN: usize = 256;
pub(crate) const BASE_PATH: &str = "/dns-query";
pub(crate) const MEDIA_TYPE: &str = "application/dns-message";

/// The token in `/dns-query/{token}`. `Ok(None)` for the bare path, `Err` for any other path.
pub(crate) fn path_token(path: &str) -> Result<Option<&str>, ()> {
    let Some(rest) = path.strip_prefix(BASE_PATH) else {
        return Err(());
    };
    match rest.strip_prefix('/') {
        _ if rest.is_empty() => Ok(None),
        Some(token) if !token.is_empty() && !token.contains('/') => Ok(Some(token)),
        _ => Err(()),
    }
}

/// The bearer token of an `Authorization` header value (scheme is case-insensitive).
pub(crate) fn bearer(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// Whether a `Content-Type` value is `application/dns-message` (parameters are ignored).
pub(crate) fn is_dns_message(value: &str) -> bool {
    value
        .split(';')
        .next()
        .is_some_and(|t| t.trim().eq_ignore_ascii_case(MEDIA_TYPE))
}

/// Decodes the `dns` query parameter (base64url, no padding).
pub(crate) fn decode_get(query: Option<&str>) -> Result<Vec<u8>, ()> {
    let value = query
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("dns=")))
        .ok_or(())?;
    if value.is_empty() || value.len() > MAX_DNS_PARAM {
        return Err(());
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| ())?;
    (bytes.len() <= MAX_MESSAGE).then_some(bytes).ok_or(())
}

/// Smallest TTL over every record of the response (RFC 8484 section 5.1); 0 without records.
pub(crate) fn min_ttl(message: &Message) -> u32 {
    message
        .answers
        .iter()
        .chain(&message.authority)
        .chain(&message.additional)
        .map(|r| r.ttl)
        .min()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_tokens() {
        assert_eq!(path_token("/dns-query"), Ok(None));
        assert_eq!(path_token("/dns-query/abc_D-1"), Ok(Some("abc_D-1")));
        assert!(path_token("/dns-query/").is_err());
        assert!(path_token("/dns-query/a/b").is_err());
        assert!(path_token("/dns-queryx").is_err());
        assert!(path_token("/other").is_err());
    }

    #[test]
    fn bearer_parsing() {
        assert_eq!(bearer("Bearer t"), Some("t"));
        assert_eq!(bearer("bearer  t "), Some("t"));
        assert_eq!(bearer("Basic t"), None);
        assert_eq!(bearer("Bearer"), None);
        assert_eq!(bearer("Bearer  "), None);
    }

    #[test]
    fn content_type() {
        assert!(is_dns_message("application/dns-message"));
        assert!(is_dns_message("Application/DNS-Message; charset=x"));
        assert!(!is_dns_message("application/json"));
    }

    #[test]
    fn get_param() {
        let enc = URL_SAFE_NO_PAD.encode([1, 2, 3, 4]);
        assert_eq!(
            decode_get(Some(&format!("x=1&dns={enc}"))),
            Ok(vec![1, 2, 3, 4])
        );
        assert!(decode_get(None).is_err());
        assert!(decode_get(Some("dns=")).is_err());
        assert!(
            decode_get(Some("dns=AQIDBA==")).is_err(),
            "padding rejected"
        );
        assert!(decode_get(Some("dns=!!!")).is_err());
        let too_long = "A".repeat(MAX_DNS_PARAM + 4);
        assert!(decode_get(Some(&format!("dns={too_long}"))).is_err());
        // Within the length cap but decoding to more than 65535 octets.
        let big = URL_SAFE_NO_PAD.encode(vec![0_u8; MAX_MESSAGE + 1]);
        assert!(decode_get(Some(&format!("dns={big}"))).is_err());
        let max = URL_SAFE_NO_PAD.encode(vec![0_u8; MAX_MESSAGE]);
        assert_eq!(
            decode_get(Some(&format!("dns={max}"))).unwrap().len(),
            MAX_MESSAGE
        );
    }
}
